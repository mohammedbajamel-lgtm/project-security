import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from botocore.exceptions import ClientError

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lambda"))
from common.audit_logger import log_execution_event  # noqa: E402
from common.idempotency import (  # noqa: E402
    IdempotencyConflict,
    acquire_lock,
    make_key,
    release_lock,
)
from remediation.failure_handler import handle_failure  # noqa: E402
from remediation.rollback_registry import rollback_for  # noqa: E402
from remediation.state_machine_input import validate_input  # noqa: E402
from remediation.verification_hooks import post_execution_hook, pre_execution_hook  # noqa: E402


class Table:
    def __init__(self, conflict=False):
        self.calls = []
        self.conflict = conflict

    def put_item(self, **kwargs):
        if self.conflict:
            raise ClientError({"Error": {"Code": "ConditionalCheckFailedException"}}, "PutItem")
        self.calls.append(kwargs)

    def delete_item(self, **kwargs):
        self.calls.append(kwargs)


def test_input_validation_levels_and_expiry():
    now = datetime(2026, 1, 1, tzinfo=UTC)
    base = {"decision_id": "d", "incident_id": "i", "action": "a", "level": 1, "params": {}}
    assert validate_input(base, now=now) == base
    with pytest.raises(ValueError):
        validate_input({**base, "level": 2}, now=now)
    with pytest.raises(ValueError):
        validate_input({**base, "expires_at": (now - timedelta(seconds=1)).isoformat()}, now=now)


def test_idempotency_and_audit():
    table = Table()
    key = make_key("i", "a", "p")
    acquire_lock(table, key, "a", "e", now=datetime(2026, 1, 1, tzinfo=UTC))
    release_lock(table, key, "a")
    assert len(table.calls) == 2
    with pytest.raises(IdempotencyConflict):
        acquire_lock(Table(True), key, "a", "e")
    assert (
        log_execution_event(
            table, "e", {"stage": "STARTED", "incident_id": "i", "action": "a", "actor": "arn"}
        )["expires_at"]
        > 0
    )


def test_rollback_and_hooks():
    assert rollback_for("enable_cloudtrail_logging") is None
    assert (
        handle_failure("disable_iam_key", {"key": "x"}, {"enable_iam_key": lambda state: state})[
            "status"
        ]
        == "ROLLED_BACK"
    )
    assert (
        handle_failure(
            "disable_iam_key",
            {},
            {"enable_iam_key": lambda _x: (_ for _ in ()).throw(RuntimeError("x"))},
        )["reason"]
        == "rollback_failed"
    )
    assert pre_execution_hook(
        {"status": "REMEDIATING"}, {"valid": True}, {"exists": True, "vulnerable": True}
    )["passed"]
    assert not post_execution_hook({"exists": True, "secure": False})["passed"]
