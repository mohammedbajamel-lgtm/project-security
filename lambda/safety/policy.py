"""Phase 9 approved-action allowlist and deterministic checks."""

from __future__ import annotations

import hashlib
import json
from typing import Any

APPROVED_ACTIONS = {
    "disable_iam_key": "L2",
    "revoke_security_group_ingress": "L2",
    "block_s3_public_access": "L1",
    "isolate_ec2_instance": "L2",
    "enable_cloudtrail_logging": "L1",
    "detach_privilege_escalation_policy": "L2",
}


def evaluate(action: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    """Return a decision only. No AWS mutation client is accepted or called."""
    reasons = []
    action_name = action.get("action")
    if action_name not in APPROVED_ACTIONS:
        reasons.append("action_not_allowlisted")
    if float(action.get("confidence", 0)) < 0.8:
        reasons.append("confidence_below_threshold")
    if not action.get("rationale"):
        reasons.append("missing_rationale")
    if context.get("investigation_status") != "ACCEPTED":
        reasons.append("investigation_not_accepted")
    if context.get("protected_resource"):
        reasons.append("protected_resource")
    decision = "DENIED" if reasons else "APPROVED"
    payload = {"action": action, "incident_id": context.get("incident_id")}
    return {
        "decision_id": hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest(),
        "decision": decision,
        "approval_level": APPROVED_ACTIONS.get(action_name),
        "reasons": reasons,
        "requires_human_approval": APPROVED_ACTIONS.get(action_name) == "L2",
    }
