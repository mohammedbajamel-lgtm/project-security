"""Read-only IAM policy simulation with a five-minute cache."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

_CACHE = {}
DEFAULT_ACTIONS = [
    "s3:GetObject",
    "s3:DeleteBucket",
    "iam:CreateUser",
    "sts:AssumeRole",
    "kms:Decrypt",
]


def simulate_permissions(
    principal_arn: str, action_filter=None, *, iam, now=time.monotonic
) -> dict:
    actions = action_filter or DEFAULT_ACTIONS
    key = (principal_arn, tuple(actions))
    if key in _CACHE and now() - _CACHE[key][0] < 300:
        return _CACHE[key][1]
    try:
        response = iam.simulate_principal_policy(PolicySourceArn=principal_arn, ActionNames=actions)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in {"NoSuchEntity", "InvalidInput"}:
            return {"error": "principal_not_found"}
        raise
    result = {
        "allowed_actions": [],
        "denied_actions": [],
        "implicit_denied": [],
        "analysis_method": "simulator",
        "confidence": "high",
    }
    for item in response.get("EvaluationResults", []):
        decision = item["EvalDecision"]
        target = (
            "allowed_actions"
            if decision == "allowed"
            else "denied_actions"
            if decision == "explicitDeny"
            else "implicit_denied"
        )
        result[target].append(item["EvalActionName"])
    _CACHE[key] = (now(), result)
    return result
