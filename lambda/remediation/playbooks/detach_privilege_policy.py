"""Detach one recently attached, evidence-backed managed policy from an IAM role."""

from __future__ import annotations

from datetime import datetime


def _role_name(role_arn: str) -> str:
    if ":role/" not in role_arn:
        raise ValueError("invalid role ARN")
    return role_arn.split(":role/", 1)[1].rsplit("/", 1)[-1]


def _attached(iam, role_name: str) -> list[dict]:
    return iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])


def detach_policy(
    iam,
    role_arn: str,
    policy_arn: str,
    *,
    approved: bool,
    evidence: dict,
) -> dict:
    if not approved:
        raise PermissionError("approved safety decision required")
    if role_arn != evidence.get("role_arn") or policy_arn not in evidence.get(
        "affected_resources", []
    ):
        raise PermissionError("policy attachment is not supported by investigation evidence")
    try:
        attached_at = datetime.fromisoformat(evidence["attached_at"].replace("Z", "+00:00"))
        start = datetime.fromisoformat(evidence["incident_start"].replace("Z", "+00:00"))
        end = datetime.fromisoformat(evidence["incident_end"].replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError) as exc:
        raise PermissionError("policy attachment time evidence is incomplete") from exc
    if not start <= attached_at <= end:
        raise PermissionError("policy was attached outside the incident window")

    role_name = _role_name(role_arn)
    iam.get_role(RoleName=role_name)
    policies = _attached(iam, role_name)
    pre_state = {"role_arn": role_arn, "attached_policies": policies}
    if policy_arn not in {policy["PolicyArn"] for policy in policies}:
        return {"changed": False, "status": "DETACHED", "pre_remediation_state": pre_state}
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        if policy_arn in {policy["PolicyArn"] for policy in _attached(iam, role_name)}:
            raise RuntimeError("policy detachment verification failed")
        iam.get_role(RoleName=role_name)
    except Exception:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        raise
    return {
        "changed": True,
        "status": "DETACHED",
        "pre_remediation_state": pre_state,
        "audit": {"role_arn": role_arn, "policy_arn": policy_arn},
    }
