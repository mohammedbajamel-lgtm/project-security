import json
import sys
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lambda"))
from approval.approval_handler import handle_request  # noqa: E402
from approval.decision_manager import (  # noqa: E402
    approve_decision,
    create_pending_decision,
    expire_pending,
    reject_decision,
)
from approval.self_approval_checker import check_self_approval  # noqa: E402
from approval.stepfunctions_callback import send_callback  # noqa: E402

NOW = datetime(2026, 9, 4, 12, tzinfo=UTC)


class Table:
    def __init__(self):
        self.items = {}

    def put_item(self, **kwargs):
        item = kwargs["Item"]
        if item["decision_id"] in self.items:
            raise RuntimeError("conditional failure")
        self.items[item["decision_id"]] = dict(item)

    def query(self, **kwargs):
        item = self.items.get(kwargs["ExpressionAttributeValues"][":decision_id"])
        return {"Items": [item] if item else []}

    def update_item(self, **kwargs):
        item = self.items[kwargs["Key"]["decision_id"]]
        if item["status"] != "PENDING":
            raise RuntimeError("conditional failure")
        values = kwargs["ExpressionAttributeValues"]
        item["status"] = values.get(":approved", values.get(":rejected", values.get(":expired")))
        if ":by" in values:
            item.update(approved_by=values[":by"], approved_at=values[":at"])
        if ":reason" in values:
            item["rejection_reason"] = values[":reason"]

    def scan(self, **_kwargs):
        return {"Items": list(self.items.values())}


def pending(table, **extra):
    return create_pending_decision(
        table,
        {
            "decision_id": "d-1",
            "incident_id": "i-1",
            "affected_principals": ["arn:bad"],
            **extra,
        },
        callback_token="opaque-task-token",  # noqa: S106
        now=NOW,
    )


def test_create_and_approve_valid_decision():
    table = Table()
    item = pending(table, investigation_report={"confidence": 1.0})
    assert item["status"] == "PENDING"
    assert item["investigation_report"]["confidence"] == 1.0
    assert table.items["d-1"]["investigation_report"]["confidence"] == Decimal("1.0")
    result = approve_decision(table, "d-1", "arn:good", now=NOW)
    assert result["status"] == "APPROVED" and result["approved_by"] == "arn:good"


def test_pending_collection_accepts_null_path_parameters():
    table = Table()
    pending(table)
    event = {
        "httpMethod": "GET",
        "resource": "/decisions/pending",
        "pathParameters": None,
        "queryStringParameters": None,
        "requestContext": {
            "authorizer": {"claims": {"cognito:groups": "cloudsec_approver"}}
        },
    }
    response = handle_request(event, manager=None, table=table, callback=None)
    assert response["statusCode"] == 200
    assert json.loads(response["body"])["Items"][0]["decision_id"] == "d-1"


def test_expired_and_self_approval_are_denied_and_audited():
    table = Table()
    pending(table)
    with pytest.raises(PermissionError, match="expired"):
        approve_decision(table, "d-1", "arn:good", now=datetime(2026, 9, 6, tzinfo=UTC))
    events = []
    with pytest.raises(PermissionError, match="self_approval"):
        approve_decision(table, "d-1", "arn:bad", now=NOW, audit=events.append)
    assert events[0]["decision_id"] == "d-1"


def test_role_chain_self_approval_and_duplicate_are_denied():
    role = "arn:aws:iam::123:role/BadRole"
    decision = {"status": "PENDING", "affected_principals": [role]}
    result = check_self_approval(decision, "arn:aws:sts::123:assumed-role/BadRole/s")
    assert not result["allowed"]
    assert check_self_approval({"status": "APPROVED"}, "arn:good")["reason"] == "duplicate_decision"


def test_reject_and_expiry_scan():
    table = Table()
    pending(table)
    assert reject_decision(table, "d-1", "arn:good", "unsafe", now=NOW)["status"] == "REJECTED"
    table = Table()
    pending(table)
    events = []
    expired = expire_pending(table, now=datetime(2026, 9, 6, tzinfo=UTC), on_expired=events.append)
    assert expired[0]["status"] == "EXPIRED" and events


class SFN:
    def __init__(self):
        self.calls = []

    def send_task_success(self, **kwargs):
        self.calls.append(("success", kwargs))

    def send_task_failure(self, **kwargs):
        self.calls.append(("failure", kwargs))


def test_approval_and_rejection_callbacks():
    base = {
        "decision_id": "d-1",
        "expires_at": "2026-09-05T12:00:00+00:00",
        "callback_token": "secret",
        "approved_by": "arn:good",
        "approved_at": NOW.isoformat(),
    }
    sfn = SFN()
    send_callback(
        sfn,
        {**base, "status": "APPROVED", "level": Decimal("2")},
        approved=True,
        now=NOW,
    )
    send_callback(
        sfn, {**base, "status": "REJECTED", "rejection_reason": "no"}, approved=False, now=NOW
    )
    assert [call[0] for call in sfn.calls] == ["success", "failure"]
    callback_output = json.loads(sfn.calls[0][1]["output"])
    assert callback_output["decision_id"] == "d-1" and callback_output["level"] == 2
    assert "callback_token" not in callback_output


def test_expired_callback_is_denied():
    with pytest.raises(PermissionError, match="expired"):
        send_callback(
            SFN(),
            {
                "status": "APPROVED",
                "expires_at": "2026-09-03T00:00:00+00:00",
                "callback_token": "secret",
            },
            approved=True,
            now=NOW,
        )


def event(method, groups, resource="/decisions/pending", decision_id=None, body=None):
    return {
        "httpMethod": method,
        "resource": resource,
        "pathParameters": {"decision_id": decision_id} if decision_id else {},
        "queryStringParameters": {},
        "body": body,
        "requestContext": {
            "authorizer": {"claims": {"cognito:groups": groups, "custom:principal_arn": "arn:good"}}
        },
    }


def test_handler_authorization_pagination_approve_and_reject():
    table = Table()
    pending(table)
    manager = SimpleNamespace(
        get_decision=lambda t, key: t.query(ExpressionAttributeValues={":decision_id": key})[
            "Items"
        ][0],
        approve_decision=lambda *_args: {
            **table.items["d-1"],
            "status": "APPROVED",
            "approved_by": "arn:good",
            "approved_at": NOW.isoformat(),
        },
        reject_decision=lambda *_args: {
            **table.items["d-1"],
            "status": "REJECTED",
            "rejection_reason": "no",
        },
    )
    callbacks = []

    def callback(decision, approved):
        callbacks.append((decision, approved))

    denied = handle_request(
        event("POST", "cloudsec_viewer"), manager=manager, table=table, callback=callback
    )
    assert denied["statusCode"] == 403
    assert (
        handle_request(
            event("GET", "cloudsec_viewer"), manager=manager, table=table, callback=callback
        )["statusCode"]
        == 200
    )
    response = handle_request(
        event("GET", "cloudsec_viewer"), manager=manager, table=table, callback=callback
    )
    assert "callback_token" not in response["body"]
    approve = event("POST", "cloudsec_approver", "/decisions/{decision_id}/approve", "d-1")
    assert (
        handle_request(approve, manager=manager, table=table, callback=callback)["statusCode"]
        == 200
    )
    reject = event(
        "POST", "cloudsec_approver", "/decisions/{decision_id}/reject", "d-1", '{"reason":"no"}'
    )
    assert (
        handle_request(reject, manager=manager, table=table, callback=callback)["statusCode"] == 200
    )
    assert [approved for _, approved in callbacks] == [True, False]
