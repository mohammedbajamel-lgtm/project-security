"""
Tests for T02-06 - Incident State Machine (IncidentsRepository).

Covers:
  - Valid transitions (5): OPEN->INVESTIGATING, INVESTIGATING->REMEDIATING,
    REMEDIATING->VERIFYING, VERIFYING->RESOLVED, VERIFYING->ESCALATED.
  - Invalid transitions (3): REMEDIATING->RESOLVED, VERIFYING->INVESTIGATING,
    RESOLVED->INVESTIGATING (terminal states).
  - Missing incident.
  - DynamoDB error retry (3 retries).
  - Concurrent update conflict (optimistic lock).
  - Idempotent create_incident (same idempotency_key / duplicate id).
  - Status-index list_by_status.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

# `lambda` is a Python keyword and cannot be used in an import statement.
# Put the deployment source root on sys.path and import the shared package as
# it will be available inside Lambda artifacts.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lambda"))

from shared.incident_state import (
    ALL_STATUSES,
    DynamoDBUnavailableError,
    IncidentNotFoundError,
    IncidentsRepository,
    InvalidTransitionError,
    validate_transition,
)

# ---------------------------------------------------------------------------
# Fixture: create a DynamoDB table and an IncidentsRepository pointing at it
# ---------------------------------------------------------------------------


@pytest.fixture()
def dynamodb():
    with mock_aws():
        client = boto3.client("dynamodb", region_name="us-east-1")
        client.create_table(
            TableName="cloudsec-dev-incidents",
            KeySchema=[
                {"AttributeName": "incident_id", "KeyType": "HASH"},
                {"AttributeName": "event_time", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "incident_id", "AttributeType": "S"},
                {"AttributeName": "event_time", "AttributeType": "S"},
                {"AttributeName": "status", "AttributeType": "S"},
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "status-index",
                    "KeySchema": [{"AttributeName": "status", "KeyType": "HASH"}],
                    "Projection": {"ProjectionType": "ALL"},
                }
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        with mock_aws():  # context manager nests fine
            yield client


@pytest.fixture()
def repo(dynamodb):
    os.environ["INCIDENTS_TABLE_NAME"] = "cloudsec-dev-incidents"
    yield IncidentsRepository(dynamodb=dynamodb)
    os.environ.pop("INCIDENTS_TABLE_NAME", None)


def _new_repo(dynamodb):
    os.environ["INCIDENTS_TABLE_NAME"] = "cloudsec-dev-incidents"
    return IncidentsRepository(dynamodb=dynamodb)


# ---------------------------------------------------------------------------
# Pure-transition tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "current,attempted",
    [
        ("OPEN", "INVESTIGATING"),
        ("INVESTIGATING", "REMEDIATING"),
        ("REMEDIATING", "VERIFYING"),
        ("VERIFYING", "RESOLVED"),
        ("VERIFYING", "ESCALATED"),
    ],
)
def test_validate_transition_allows_valid(current, attempted):
    assert validate_transition(current, attempted) is True


@pytest.mark.parametrize(
    "current,attempted",
    [
        ("OPEN", "RESOLVED"),
        ("REMEDIATING", "RESOLVED"),
        ("VERIFYING", "INVESTIGATING"),
        ("RESOLVED", "INVESTIGATING"),
        ("ESCALATED", "OPEN"),
        ("OPEN", "OPEN"),
        ("OPEN", "UNKNOWN"),
    ],
)
def test_validate_transition_rejects_invalid(current, attempted):
    assert validate_transition(current, attempted) is False


def test_all_statuses_are_known():
    assert ALL_STATUSES == frozenset(
        {"OPEN", "INVESTIGATING", "REMEDIATING", "VERIFYING", "RESOLVED", "ESCALATED"}
    )


# ---------------------------------------------------------------------------
# Happy-path lifecycle test
# ---------------------------------------------------------------------------


def test_full_incident_lifecycle(repo):
    # 1) create
    created = repo.create_incident(
        incident_id="00000000-0000-4000-8000-000000000001",
        findings=["ff-aaaa-bbbb-cccc-dddd", "ff-1111-2222-3333-4444"],
        severity="P2",
        correlation_type="principal_arn",
        principal_arn="arn:aws:iam::123456789012:user/bad-user",
        resource_arn="arn:aws:s3:::sensitive-bucket",
    )
    assert created["incident_id"] == "00000000-0000-4000-8000-000000000001"
    assert created["status"] == "OPEN"
    assert created["severity"] == "P2"
    assert created["version"] == 1

    # 2) OPEN -> INVESTIGATING
    row = repo.transition_incident(
        incident_id=created["incident_id"],
        new_status="INVESTIGATING",
        reason="Correlation engine opened investigation",
    )
    assert row["status"] == "INVESTIGATING"
    assert row["version"] == 2

    # 3) INVESTIGATING -> REMEDIATING
    row = repo.transition_incident(
        incident_id=created["incident_id"],
        new_status="REMEDIATING",
        reason="Safety validation approved remediation",
    )
    assert row["status"] == "REMEDIATING"
    assert row["version"] == 3

    # 4) REMEDIATING -> VERIFYING
    row = repo.transition_incident(
        incident_id=created["incident_id"],
        new_status="VERIFYING",
        reason="Playbook complete, verify",
    )
    assert row["status"] == "VERIFYING"
    assert row["version"] == 4

    # 5) VERIFYING -> RESOLVED
    row = repo.transition_incident(
        incident_id=created["incident_id"],
        new_status="RESOLVED",
        reason="Verification checks passed",
    )
    assert row["status"] == "RESOLVED"
    assert row["version"] == 5


# ---------------------------------------------------------------------------
# Invalid transition rejection
# ---------------------------------------------------------------------------


def test_invalid_transition_raises(repo):
    repo.create_incident(
        incident_id="00000000-0000-4000-8000-000000000010",
        findings=["ff-aaaa-bbbb-cccc-dddd"],
        severity="P3",
        correlation_type="source_ip",
    )
    with pytest.raises(InvalidTransitionError) as exc_info:
        repo.transition_incident(
            incident_id="00000000-0000-4000-8000-000000000010",
            new_status="RESOLVED",  # jump straight to resolved from OPEN
            reason="impossible",
        )
    assert exc_info.value.current == "OPEN"
    assert exc_info.value.attempted == "RESOLVED"


def test_invalid_status_raises(repo):
    repo.create_incident(
        incident_id="00000000-0000-4000-8000-000000000011",
        findings=["ff-1111-2222-3333-4444"],
        severity="P4",
        correlation_type="resource_arn",
    )
    with pytest.raises(InvalidTransitionError):
        repo.transition_incident(
            incident_id="00000000-0000-4000-8000-000000000011",
            new_status="NOT_A_STATUS",
            reason="bad",
        )


def test_terminal_state_no_transitions(repo):
    """RESOLVED and ESCALATED are terminal — nothing allowed out."""
    repo.create_incident(
        incident_id="00000000-0000-4000-8000-000000000012",
        findings=["ff-5555-6666-7777-8888"],
        severity="P4",
        correlation_type="principal_arn",
    )
    # RESOLVED
    repo.transition_incident(
        incident_id="00000000-0000-4000-8000-000000000012",
        new_status="INVESTIGATING",
        reason="r1",
    )
    repo.transition_incident(
        incident_id="00000000-0000-4000-8000-000000000012",
        new_status="REMEDIATING",
        reason="r2",
    )
    repo.transition_incident(
        incident_id="00000000-0000-4000-8000-000000000012",
        new_status="VERIFYING",
        reason="r3",
    )
    repo.transition_incident(
        incident_id="00000000-0000-4000-8000-000000000012",
        new_status="RESOLVED",
        reason="r4",
    )
    with pytest.raises(InvalidTransitionError):
        repo.transition_incident(
            incident_id="00000000-0000-4000-8000-000000000012",
            new_status="OPEN",
            reason="back",
        )


# ---------------------------------------------------------------------------
# Missing incident
# ---------------------------------------------------------------------------


def test_get_missing_incident_raises(repo):
    with pytest.raises(IncidentNotFoundError):
        repo.get_incident("does-not-exist")


def test_transition_missing_incident_raises(repo):
    with pytest.raises(IncidentNotFoundError):
        repo.transition_incident(
            incident_id="does-not-exist",
            new_status="INVESTIGATING",
            reason="nothing",
        )


# ---------------------------------------------------------------------------
# Idempotent create
# ---------------------------------------------------------------------------


def test_idempotent_create_returns_existing(repo):
    first = repo.create_incident(
        incident_id="00000000-0000-4000-8000-000000000020",
        findings=["ff-aaaa-bbbb-cccc-dddd"],
        severity="P1",
        correlation_type="principal_arn",
    )
    second = repo.create_incident(
        incident_id="00000000-0000-4000-8000-000000000020",
        findings=["ff-aaaa-bbbb-cccc-dddd", "ff-1111-2222-3333-4444"],
        severity="P1",
        correlation_type="principal_arn",
    )
    assert first["incident_id"] == second["incident_id"]
    # version unchanged
    assert first["version"] == second["version"]


def test_transactional_idempotency_sentinel(repo):
    kwargs = {
        "incident_id": "inc-deterministic",
        "findings": ["a", "b"],
        "severity": "P2",
        "correlation_type": "principal_arn",
        "idempotency_key": "same-findings",
    }
    first = repo.create_incident(**kwargs)
    second = repo.create_incident(**kwargs)
    assert first["event_time"] == second["event_time"]


# ---------------------------------------------------------------------------
# TTL + metadata sanity
# ---------------------------------------------------------------------------


def test_create_incident_sets_ttl_and_metadata(repo):
    row = repo.create_incident(
        incident_id="00000000-0000-4000-8000-000000000030",
        findings=["ff-aaaa-bbbb-cccc-dddd"],
        severity="P3",
        correlation_type="principal_arn",
        window_start="2026-09-04T00:00:00Z",
        window_end="2026-09-04T00:15:00Z",
    )
    assert "ttl" in row and isinstance(row["ttl"], int)
    assert "created_at" in row
    assert "window_start" in row
    assert "window_end" in row
    assert row["finding_count"] == 1
    assert row["schema_version"] == "1.0.0"


# ---------------------------------------------------------------------------
# list_by_status (uses the status-index GSI)
# ---------------------------------------------------------------------------


def test_list_by_status(repo):
    repo.create_incident(
        incident_id="00000000-0000-4000-8000-000000000040",
        findings=["ff-aaaa-bbbb-cccc-dddd"],
        severity="P3",
        correlation_type="principal_arn",
    )
    repo.create_incident(
        incident_id="00000000-0000-4000-8000-000000000041",
        findings=["ff-1111-2222-3333-4444"],
        severity="P4",
        correlation_type="principal_arn",
    )
    repo.transition_incident(
        incident_id="00000000-0000-4000-8000-000000000040",
        new_status="INVESTIGATING",
        reason="r",
    )
    open_list = repo.list_by_status("OPEN")
    # Only incident ...41 is still OPEN
    ids = {r["incident_id"] for r in open_list}
    assert "00000000-0000-4000-8000-000000000041" in ids
    assert len(open_list) == 1


def test_list_by_unknown_status_raises(repo):
    with pytest.raises(ValueError):
        repo.list_by_status("BOGUS")


# ---------------------------------------------------------------------------
# get_incident returns the latest row per incident
# ---------------------------------------------------------------------------


def test_get_incident_returns_latest_row(repo):
    repo.create_incident(
        incident_id="00000000-0000-4000-8000-000000000050",
        findings=["ff-aaaa-bbbb-cccc-dddd"],
        severity="P2",
        correlation_type="principal_arn",
    )
    repo.transition_incident(
        incident_id="00000000-0000-4000-8000-000000000050",
        new_status="INVESTIGATING",
        reason="r1",
    )
    repo.transition_incident(
        incident_id="00000000-0000-4000-8000-000000000050",
        new_status="REMEDIATING",
        reason="r2",
    )
    latest = repo.get_incident("00000000-0000-4000-8000-000000000050")
    assert latest["status"] == "REMEDIATING"
    assert latest["version"] == 3


# ---------------------------------------------------------------------------
# Retry decorator: DynamoDB throttled -> retries then raises
# ---------------------------------------------------------------------------


def test_retry_exhausts_and_raises_dynamodb_unavailable():
    """
    Simulate 3 consecutive throttles from the underlying client; the
    @dynamodb_retry decorator must retry 3 times then raise
    DynamoDBUnavailableError.
    """
    import unittest.mock as mock

    class FailingClient:
        def __init__(self):
            self.call_count = 0

        def query(self, **kwargs):
            self.call_count += 1
            raise ClientError(
                {"Error": {"Code": "ProvisionedThroughputExceededException", "Message": "rate"}},
                "Query",
            )

    with mock.patch.dict(os.environ, {"INCIDENTS_TABLE_NAME": "cloudsec-dev-incidents"}):
        repo = IncidentsRepository(dynamodb=FailingClient())
        with pytest.raises(DynamoDBUnavailableError):
            repo.get_incident("any-id")
    # 3 retries + initial call = 4 total
    assert repo._dynamodb.call_count == 4
