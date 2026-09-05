"""Prevent compromised identities and their role chains from approving remediation."""

from __future__ import annotations


def principal_chain(arn: str, session_issuer_arn: str | None = None) -> set[str]:
    principals = {arn}
    if session_issuer_arn:
        principals.add(session_issuer_arn)
    if ":assumed-role/" in arn:
        account, path = arn.split(":assumed-role/", 1)
        role_name = path.split("/", 1)[0]
        principals.add(f"{account.replace(':sts:', ':iam:')}:role/{role_name}")
    return principals


def check_self_approval(
    decision: dict,
    approver_arn: str,
    *,
    session_issuer_arn: str | None = None,
    audit=None,
) -> dict:
    if decision.get("status") != "PENDING":
        return {"allowed": False, "reason": "duplicate_decision"}
    affected = set(decision.get("affected_principals", [])) | set(
        decision.get("finding_principals", [])
    )
    identities = principal_chain(approver_arn, session_issuer_arn)
    if affected & identities:
        event = {
            "event": "self_approval_attempted",
            "approver_arn": approver_arn,
            "decision_id": decision.get("decision_id"),
            "affected_principals": sorted(affected),
        }
        if audit:
            audit(event)
        return {"allowed": False, "reason": "self_approval_attempted"}
    return {"allowed": True, "reason": "allowed"}
