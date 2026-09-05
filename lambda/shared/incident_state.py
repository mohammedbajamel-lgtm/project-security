"""
Incident state machine (T02-06).

Enforces valid incident status transitions in DynamoDB with optimistic
locking. All status transitions are atomic: a transition only applies if
the incident row still has the expected `current_status`. This prevents
lost updates when two Lambdas try to transition the same incident.

The state machine lives in the shared package so every Lambda component
(correlation-engine, investigation-engine, safety-validation,
verification-engine, reporting) uses the SAME transition rules.

Design notes
------------
* Table schema: partition key = incident_id, sort key = event_time.
  We treat the LATEST row per incident_id as the current state.
* Optimistic locking: every transition increments `version`. A failed
  transition raises InvalidTransitionError with current + attempted
  status.
* Idempotency: create_incident uses a ConditionExpression on incident_id
  so a duplicate finding set does not create a second incident.
* Retries: all DynamoDB operations are wrapped in a retry decorator
  (max 3 retries, exponential backoff from 1s).
"""

from __future__ import annotations

import functools
import logging
import os
import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import boto3
from boto3.dynamodb.types import TypeDeserializer
from botocore.config import Config
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Valid incident status transitions
# ---------------------------------------------------------------------------

#: State transition map. Values are the ALLOWED next states.
#: Any transition not listed here is rejected atomically by the DynamoDB
#: ConditionExpression and surfaces as InvalidTransitionError.
VALID_TRANSITIONS: dict[str, tuple[str, ...]] = {
    "OPEN": ("INVESTIGATING",),
    "INVESTIGATING": ("REMEDIATING",),
    "REMEDIATING": ("VERIFYING",),
    "VERIFYING": ("RESOLVED", "ESCALATED"),
    "ESCALATED": (),  # Terminal (human must take over)
    "RESOLVED": (),  # Terminal
}

ALL_STATUSES = frozenset(VALID_TRANSITIONS.keys())

#: Default TTL (seconds from creation) applied to new incidents.
DEFAULT_INCIDENT_TTL_SECONDS = 30 * 24 * 3600  # 30 days


class InvalidTransitionError(Exception):
    """Raised when a status transition is not in VALID_TRANSITIONS or fails optimistic lock."""

    def __init__(self, incident_id: str, current: str, attempted: str):
        self.incident_id = incident_id
        self.current = current
        self.attempted = attempted
        super().__init__(
            f"Invalid incident transition {current!r} -> {attempted!r} "
            f"for incident {incident_id}"
        )


class IncidentNotFoundError(Exception):
    """Raised when get_incident is called for an unknown incident_id."""

    def __init__(self, incident_id: str):
        self.incident_id = incident_id
        super().__init__(f"Incident not found: {incident_id}")


class DynamoDBUnavailableError(Exception):
    """Raised after all retries are exhausted when talking to DynamoDB."""


# ---------------------------------------------------------------------------
# DynamoDB retry decorator
# ---------------------------------------------------------------------------


def dynamodb_retry(
    max_retries: int = 3,
    base_delay: float = 1.0,
) -> Callable:
    """Decorator: retry DynamoDB calls on transient throttling errors."""

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_exc: Exception | None = None
            # max_retries is the number of retries after the initial attempt.
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except ClientError as exc:
                    code = exc.response.get("Error", {}).get("Code", "")
                    if code not in {
                        "ProvisionedThroughputExceededException",
                        "RequestLimitExceeded",
                    }:
                        raise
                    last_exc = exc
                    if attempt == max_retries:
                        break
                    delay = base_delay * (2**attempt)
                    logger.warning(
                        "DynamoDB throttled (%s), retrying in %.2fs (attempt %d/%d)",
                        code,
                        delay,
                        attempt + 1,
                        max_retries,
                    )
                    time.sleep(delay)
            assert last_exc is not None
            raise DynamoDBUnavailableError(
                f"DynamoDB still unavailable after {max_retries} retries: {last_exc}"
            ) from last_exc

        return wrapper

    return decorator


# ---------------------------------------------------------------------------
# Client construction (singleton per (table, endpoint))
# ---------------------------------------------------------------------------


class IncidentsRepository:
    """Thin DynamoDB wrapper around the incidents table with optimistic locking.

    Env vars:
      INCIDENTS_TABLE_NAME       - required
      AWS_REGION                 - optional, defaults to os.getenv("AWS_REGION") or "us-east-1"
    """

    def __init__(self, dynamodb=None, table_name: str | None = None):
        """
        Parameters
        ----------
        dynamodb:
            Optional boto3 DynamoDB client for testing (injectable).
        table_name:
            Table name override. Defaults to INCIDENTS_TABLE_NAME env var.
        """
        table_name = table_name or os.getenv("INCIDENTS_TABLE_NAME")
        if not table_name:
            raise ValueError(
                "INCIDENTS_TABLE_NAME environment variable is required "
                "for the incidents repository"
            )
        self.table_name = table_name
        if dynamodb is None:
            dynamodb = boto3.client(
                "dynamodb",
                config=Config(retries={"max_attempts": 1}),  # we handle retries ourselves
                region_name=os.getenv("AWS_REGION", "us-east-1"),
            )
        self._dynamodb = dynamodb

    # ---- Public API ----

    @dynamodb_retry()
    def create_incident(
        self,
        *,
        incident_id: str,
        findings: Sequence[dict[str, Any]],
        severity: str,
        correlation_type: str,
        principal_arn: str | None = None,
        resource_arn: str | None = None,
        source_ip: str | None = None,
        window_start: str | None = None,
        window_end: str | None = None,
        ttl: int = DEFAULT_INCIDENT_TTL_SECONDS,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """Create a new incident row. Idempotent on `incident_id`.

        If `incident_id` already exists, the call is a no-op and returns
        the existing row. Callers can pre-check with `get_incident` if
        they need to know whether a duplicate was skipped.
        """
        now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        created_at = now
        ttl_seconds = int(datetime.now(UTC).timestamp()) + ttl

        item = {
            "incident_id": {"S": str(incident_id)},
            "event_time": {"S": now},
            "status": {"S": "OPEN"},
            "severity": {"S": severity},
            "correlation_type": {"S": correlation_type},
            "finding_ids": {"L": [{"S": str(f)} for f in findings]},
            "finding_count": {"N": str(len(findings))},
            "created_at": {"S": created_at},
            "ttl": {"N": str(ttl_seconds)},
            "version": {"N": "1"},
            "schema_version": {"S": "1.0.0"},
        }
        if principal_arn:
            item["principal_arn"] = {"S": principal_arn}
        if resource_arn:
            item["resource_arn"] = {"S": resource_arn}
        if source_ip:
            item["source_ip"] = {"S": source_ip}
        if window_start:
            item["window_start"] = {"S": window_start}
        if window_end:
            item["window_end"] = {"S": window_end}
        if idempotency_key:
            item["idempotency_key"] = {"S": idempotency_key}

        try:
            if idempotency_key:
                sentinel = {
                    "incident_id": {"S": str(incident_id)},
                    "event_time": {"S": "#IDEMPOTENCY"},
                    "idempotency_key": {"S": idempotency_key},
                }
                self._dynamodb.transact_write_items(
                    TransactItems=[
                        {
                            "Put": {
                                "TableName": self.table_name,
                                "Item": sentinel,
                                "ConditionExpression": "attribute_not_exists(incident_id)",
                            }
                        },
                        {
                            "Put": {
                                "TableName": self.table_name,
                                "Item": item,
                                "ConditionExpression": "attribute_not_exists(incident_id)",
                            }
                        },
                    ]
                )
                return _dynamo_item_to_dict(item)
            self._dynamodb.put_item(
                TableName=self.table_name,
                Item=item,
                ConditionExpression=(
                    "attribute_not_exists(incident_id) " "AND attribute_not_exists(event_time)"
                ),
            )
            return _dynamo_item_to_dict(item)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in {
                "ConditionalCheckFailedException",
                "TransactionCanceledException",
            }:
                # Duplicate create — idempotency. Return the existing row.
                existing = self.get_incident(incident_id)
                logger.info(
                    "Incident %s already exists (idempotent create), returning existing row",
                    incident_id,
                )
                return existing
            raise

    @dynamodb_retry()
    def get_incident(self, incident_id: str) -> dict[str, Any]:
        """Return the LATEST row for an incident_id.

        Sort key is `event_time`; we query with ScanIndexForward=False
        and limit=1 to fetch the newest transition.
        """
        response = self._dynamodb.query(
            TableName=self.table_name,
            KeyConditionExpression="incident_id = :pk",
            ExpressionAttributeValues={":pk": {"S": str(incident_id)}},
            ScanIndexForward=False,
            Limit=1,
            Select="ALL_ATTRIBUTES",
        )
        items = response.get("Items", [])
        if not items:
            raise IncidentNotFoundError(incident_id)
        return _dynamo_item_to_dict(items[0])

    @dynamodb_retry()
    def transition_incident(
        self,
        *,
        incident_id: str,
        new_status: str,
        reason: str,
        changed_by: str = "cloudsec-ai",
        current_status: str | None = None,
    ) -> dict[str, Any]:
        """Transition an incident to a new status with optimistic locking.

        Uses DynamoDB UpdateItem with a ConditionExpression that asserts
        the current status still matches `current_status`. If it doesn't
        (concurrent update), the operation fails and InvalidTransitionError
        is raised with the current and attempted status.

        Parameters
        ----------
        incident_id:
            The incident to transition.
        new_status:
            Target status (must be in VALID_TRANSITIONS[current_status]).
        reason:
            Human-readable reason for the transition.
        changed_by:
            Lambda function name or principal ARN that made the change.
        current_status:
            Expected current status. If None, we look it up first and use
            that value.
        """
        if new_status not in ALL_STATUSES:
            raise InvalidTransitionError(incident_id, "?", new_status)

        current = self.get_incident(incident_id)
        actual_status = current["status"]
        if current_status is not None and current_status != actual_status:
            raise InvalidTransitionError(incident_id, actual_status, new_status)
        current_status = actual_status

        if new_status not in VALID_TRANSITIONS.get(current_status, ()):
            raise InvalidTransitionError(incident_id, current_status, new_status)

        now = datetime.now(UTC).isoformat().replace("+00:00", "Z")

        condition_expr = (
            "attribute_exists(incident_id) "
            "AND #status = :expected_status "
            "AND #version = :expected_version"
        )

        expected_status = current["status"]
        expected_version = str(current.get("version", 1))

        try:
            response = self._dynamodb.update_item(
                TableName=self.table_name,
                Key={
                    "incident_id": {"S": str(incident_id)},
                    "event_time": {"S": current["event_time"]},
                },
                # DynamoDB primary-key attributes are immutable. event_time is
                # the table sort key, so update the current row in place.
                UpdateExpression="SET #status = :new_status, #version = :new_version, "
                "changed_at = :changed_at, reason = :reason, changed_by = :changed_by",
                ConditionExpression=condition_expr,
                ExpressionAttributeNames={
                    "#status": "status",
                    "#version": "version",
                },
                ExpressionAttributeValues={
                    ":expected_status": {"S": expected_status},
                    ":expected_version": {"N": expected_version},
                    ":new_status": {"S": new_status},
                    ":new_version": {"N": str(int(expected_version) + 1)},
                    ":changed_at": {"S": now},
                    ":reason": {"S": reason},
                    ":changed_by": {"S": changed_by},
                },
                ReturnValues="ALL_NEW",
            )
            return _dynamo_item_to_dict(response["Attributes"])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                # Optimistic lock failed - someone else changed the row.
                try:
                    current_now = self.get_incident(incident_id)
                except IncidentNotFoundError:
                    raise InvalidTransitionError(incident_id, "<missing>", new_status) from exc
                raise InvalidTransitionError(
                    incident_id, current_now["status"], new_status
                ) from exc
            raise

    # ---- Helpers ----

    @dynamodb_retry()
    def list_by_status(self, status: str, *, limit: int = 100) -> list[dict[str, Any]]:
        """Query the status-index GSI to list incidents by current status."""
        if status not in ALL_STATUSES:
            raise ValueError(f"Unknown status: {status!r}")
        response = self._dynamodb.query(
            TableName=self.table_name,
            IndexName="status-index",
            KeyConditionExpression="status = :status",
            ExpressionAttributeValues={":status": {"S": status}},
            Limit=limit,
            Select="ALL_ATTRIBUTES",
        )
        return [_dynamo_item_to_dict(item) for item in response.get("Items", [])]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _dynamo_item_to_dict(item: dict[str, Any]) -> dict[str, Any]:
    """Convert a DynamoDB item (attribute-map form) to a plain dict.

    Strips DynamoDB type tags (S/N/L/M) and preserves structure for
    primitive values. Lists become Python lists of strings. Maps are
    recursively unwrapped.
    """
    deserializer = TypeDeserializer()

    def normalize(value: Any) -> Any:
        if isinstance(value, Decimal):
            return int(value) if value == value.to_integral_value() else float(value)
        if isinstance(value, list):
            return [normalize(entry) for entry in value]
        if isinstance(value, dict):
            return {key: normalize(entry) for key, entry in value.items()}
        if isinstance(value, set):
            return {normalize(entry) for entry in value}
        return value

    return {key: normalize(deserializer.deserialize(value)) for key, value in item.items()}


def validate_transition(current: str, attempted: str) -> bool:
    """Pure function: returns True if the transition is in VALID_TRANSITIONS."""
    return attempted in VALID_TRANSITIONS.get(current, ())
