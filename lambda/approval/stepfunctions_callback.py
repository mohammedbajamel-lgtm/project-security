"""Resume or fail a waiting remediation workflow using its opaque task token."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from decimal import Decimal


def _json_value(value):
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    raise TypeError(f"not JSON serializable: {type(value).__name__}")


def send_callback(stepfunctions, decision: dict, *, approved: bool, now=None) -> None:
    clock = now or datetime.now(UTC)
    if decision.get("status") not in {"APPROVED", "REJECTED"}:
        raise PermissionError("decision is not final")
    if datetime.fromisoformat(decision["expires_at"]) <= clock:
        raise PermissionError("callback token expired")
    token = decision.get("callback_token")
    if not token:
        raise ValueError("callback token missing")
    if approved:
        public_decision = {key: value for key, value in decision.items() if key != "callback_token"}
        stepfunctions.send_task_success(
            taskToken=token,
            output=json.dumps(
                {
                    **public_decision,
                    "human_approval_id": decision["decision_id"],
                },
                default=_json_value,
            ),
        )
    else:
        stepfunctions.send_task_failure(
            taskToken=token,
            error="RemediationRejected",
            cause=decision.get("rejection_reason", "rejected"),
        )
