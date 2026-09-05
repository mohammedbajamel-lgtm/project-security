"""Atomic lifecycle operations for human approval decisions."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal

from approval.self_approval_checker import check_self_approval


def _now(now=None):
    return now or datetime.now(UTC)


def _dynamodb_item(value):
    """Convert JSON numbers to DynamoDB-safe Decimal values."""
    return json.loads(json.dumps(value), parse_float=Decimal)


def create_pending_decision(table, decision: dict, *, callback_token: str, now=None) -> dict:
    created = _now(now)
    expires = created + timedelta(hours=24)
    item = {
        **decision,
        "created_at": created.isoformat(),
        "expires_at": expires.isoformat(),
        "expires_at_epoch": int(expires.timestamp()),
        "status": "PENDING",
        "callback_token": callback_token,
    }
    table.put_item(
        Item=_dynamodb_item(item),
        ConditionExpression="attribute_not_exists(decision_id)",
    )
    return item


def get_decision(table, decision_id: str) -> dict:
    items = table.query(
        KeyConditionExpression="decision_id = :decision_id",
        ExpressionAttributeValues={":decision_id": decision_id},
        ConsistentRead=True,
        Limit=1,
        ScanIndexForward=False,
    ).get("Items", [])
    item = items[0] if items else None
    if not item:
        raise ValueError("decision not found")
    return item


def approve_decision(
    table,
    decision_id: str,
    approver_arn: str,
    *,
    session_issuer_arn: str | None = None,
    audit=None,
    now=None,
) -> dict:
    decision = get_decision(table, decision_id)
    clock = _now(now)
    if datetime.fromisoformat(decision["expires_at"]) <= clock:
        raise PermissionError("decision expired")
    check = check_self_approval(
        decision,
        approver_arn,
        session_issuer_arn=session_issuer_arn,
        audit=audit,
    )
    if not check["allowed"]:
        raise PermissionError(check["reason"])
    table.update_item(
        Key={"decision_id": decision_id, "created_at": decision["created_at"]},
        UpdateExpression="SET #s=:approved, approved_by=:by, approved_at=:at",
        ConditionExpression="#s=:pending",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":approved": "APPROVED",
            ":pending": "PENDING",
            ":by": approver_arn,
            ":at": clock.isoformat(),
        },
    )
    return {
        **decision,
        "status": "APPROVED",
        "approved_by": approver_arn,
        "approved_at": clock.isoformat(),
    }


def reject_decision(table, decision_id: str, approver_arn: str, reason: str, *, now=None) -> dict:
    if not reason.strip():
        raise ValueError("rejection reason required")
    decision = get_decision(table, decision_id)
    clock = _now(now)
    if datetime.fromisoformat(decision["expires_at"]) <= clock:
        raise PermissionError("decision expired")
    table.update_item(
        Key={"decision_id": decision_id, "created_at": decision["created_at"]},
        UpdateExpression=(
            "SET #s=:rejected, approved_by=:by, approved_at=:at, " "rejection_reason=:reason"
        ),
        ConditionExpression="#s=:pending",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":rejected": "REJECTED",
            ":pending": "PENDING",
            ":by": approver_arn,
            ":at": clock.isoformat(),
            ":reason": reason,
        },
    )
    return {
        **decision,
        "status": "REJECTED",
        "approved_by": approver_arn,
        "approved_at": clock.isoformat(),
        "rejection_reason": reason,
    }


def expire_pending(table, *, now=None, on_expired=None) -> list[dict]:
    clock = _now(now)
    expired = []
    response = table.scan(
        FilterExpression="#s=:pending",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":pending": "PENDING"},
    )
    for item in response.get("Items", []):
        if datetime.fromisoformat(item["expires_at"]) <= clock:
            table.update_item(
                Key={"decision_id": item["decision_id"], "created_at": item["created_at"]},
                UpdateExpression="SET #s=:expired",
                ConditionExpression="#s=:pending",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={":expired": "EXPIRED", ":pending": "PENDING"},
            )
            changed = {**item, "status": "EXPIRED"}
            expired.append(changed)
            if on_expired:
                on_expired(changed)
    return expired
