"""Strict schema -> evidence -> policy -> risk safety chain."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta

POLICY = {
    "disable_iam_key": (
        2,
        {"user_name", "access_key_id"},
        {"UnauthorizedAccess", "UnauthorizedAPI"},
    ),
    "revoke_security_group_ingress": (
        2,
        {"group_id", "cidr", "from_port", "to_port", "protocol", "rule_id"},
        {"OpenSecurityGroup"},
    ),
    "block_s3_public_access": (1, {"bucket_name"}, {"PublicS3Bucket"}),
    "isolate_ec2_instance": (2, {"instance_id"}, {"CompromisedEC2"}),
    "enable_cloudtrail_logging": (1, {"trail_name"}, {"CloudTrailTampering"}),
    "detach_privilege_escalation_policy": (
        2,
        {"role_arn", "policy_arn"},
        {"IAMPrivilegeEscalation"},
    ),
}


def _result(level, reason, details=None):
    return {"level": level, "reason": reason, "details": details or []}


def validate_schema(rec: dict) -> dict:
    action = rec.get("action")
    if action not in POLICY:
        return _result(3, "schema_invalid", ["unknown action"])
    if not isinstance(rec.get("params"), dict):
        return _result(3, "schema_invalid", ["params must be object"])
    if set(rec["params"]) - POLICY[action][1]:
        return _result(3, "schema_invalid", ["unknown params"])
    if POLICY[action][1] - set(rec["params"]):
        return _result(3, "schema_invalid", ["missing required params"])
    if not isinstance(rec.get("confidence"), int | float) or not 0 <= rec["confidence"] <= 1:
        return _result(3, "schema_invalid", ["invalid confidence"])
    if (
        not isinstance(rec.get("rationale"), str)
        or not rec["rationale"]
        or len(rec["rationale"]) > 1000
    ):
        return _result(3, "schema_invalid", ["invalid rationale"])
    return _result(0, "valid")


def validate_evidence(rec: dict, report: dict) -> dict:
    evidence = json.dumps(report.get("evidence_citations", []))
    principals = json.dumps(report.get("affected_principals", []))
    resources = json.dumps(report.get("affected_resources", []))
    locations = {
        "user_name": principals,
        "role_arn": principals,
        "bucket_name": resources,
        "instance_id": resources,
        "access_key_id": evidence,
        "group_id": evidence,
        "cidr": evidence,
        "from_port": evidence,
        "to_port": evidence,
        "protocol": evidence,
        "rule_id": evidence,
        "trail_name": evidence,
        "policy_arn": evidence,
    }
    missing = [
        f"param {key} not found in evidence"
        for key, value in rec["params"].items()
        if str(value) not in locations.get(key, evidence)
    ]
    return _result(3, "evidence_invalid", missing) if missing else _result(0, "valid")


def execute_validation(rec: dict, report: dict, *, now=None) -> dict:
    audit = []
    for stage in (validate_schema(rec),):
        audit.append({**stage, "stage": "schema"})
        if stage["level"] == 3:
            return _decision(rec, report, stage, audit, now)
    stage = validate_evidence(rec, report)
    audit.append({**stage, "stage": "evidence"})
    if stage["level"] == 3:
        return _decision(rec, report, stage, audit, now)
    level, _, finding_types = POLICY[rec["action"]]
    if report.get("finding_type") not in finding_types:
        stage = _result(3, "policy_invalid", ["applicability condition failed"])
        audit.append({**stage, "stage": "policy"})
        return _decision(rec, report, stage, audit, now)
    factors = []
    if report.get("blast_radius", {}).get("risk_score", 0) >= 8:
        factors.append("high_blast_radius")
    if report.get("critical_resource"):
        factors.append("critical_resource")
    if report.get("cross_account"):
        factors.append("cross_account")
    clock = now or datetime.now(UTC)
    if clock.hour >= 22 or clock.hour < 6:
        factors.append("night_time")
    if factors:
        level = max(level, 2)
    stage = _result(level, "approved_policy", factors)
    audit.append({**stage, "stage": "policy_and_risk"})
    return _decision(rec, report, stage, audit, clock)


def _decision(rec, report, stage, audit, now):
    created = now or datetime.now(UTC)
    level = stage["level"]
    raw = json.dumps(
        {"incident_id": report.get("incident_id"), "recommendation": rec}, sort_keys=True
    )
    expiry = created + timedelta(hours=24) if level == 2 else None
    return {
        "decision_id": hashlib.sha256(raw.encode()).hexdigest(),
        "incident_id": report.get("incident_id"),
        "action": rec.get("action"),
        "level": level,
        "reason": stage["reason"],
        "risk_factors": stage.get("details", []),
        "created_at": created.isoformat(),
        "expires_at": expiry.isoformat() if expiry else None,
        "expires_at_epoch": int(expiry.timestamp()) if expiry else 0,
        "audit_trail": audit,
        "event_type": {
            1: "RemediationApproved",
            2: "RemediationApprovalRequired",
            3: "RemediationRejected",
        }[level],
    }
