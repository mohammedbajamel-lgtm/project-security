"""Canonical Phase 19 scenario registry and requirement traceability."""

from __future__ import annotations

import os

LAB_ACCOUNT_ID = os.environ.get("CLOUDSEC_LAB_ACCOUNT_ID", "")
SSM_PREFIX = "/cloudsec/lab/e2e/"
SCENARIO_TIMEOUT_SECONDS = 600

INCIDENT_TYPES = (
    "compromised_iam_key",
    "security_group_change",
    "public_s3_exposure",
    "ec2_compromise",
    "cloudtrail_tampering",
    "privilege_escalation",
)

SCENARIO_CONFIGS = {
    "level1_auto_remediation": {
        "expected": "RESOLVED",
        "level": 1,
        "requirements": [
            "R1",
            "R2",
            "R4",
            "R6",
            "R7",
            "R8",
            "R9",
            "R10",
            "R11",
            "R13",
            "R14",
            "R15",
        ],
    },
    "level2_approval": {
        "expected": "RESOLVED",
        "level": 2,
        "requirements": ["R2", "R6", "R9", "R10", "R11", "R12", "R13", "R14", "R15"],
    },
    "level2_rejection": {"expected": "ESCALATED", "level": 2, "requirements": ["R9", "R12", "R13"]},
    "level3_rejected_action": {"expected": "ESCALATED", "level": 3, "requirements": ["R6", "R9"]},
    "malformed_bedrock": {"expected": "ESCALATED", "requirements": ["R2", "R6"]},
    "transient_failures": {"expected": "RESOLVED_OR_ESCALATED", "requirements": ["R2", "R6"]},
    "failed_remediation_rollback": {"expected": "ESCALATED", "requirements": ["R10", "R13", "R14"]},
    "failed_verification": {"expected": "ESCALATED", "requirements": ["R13", "R14", "R15"]},
    "duplicate_events": {"expected": "IDEMPOTENT", "requirements": ["R1", "R2", "R10"]},
    "cross_account_events": {"expected": "ISOLATED", "requirements": ["R1", "R4", "R7", "R8"]},
    "insufficient_evidence": {"expected": "ESCALATED", "level": 3, "requirements": ["R6", "R9"]},
    "dlq_retry": {"expected": "DLQ", "requirements": ["R1", "R17"]},
}

REQUIRED_SSM_KEYS = {
    "account_id",
    "region",
    "environment",
    "resource_prefix",
    "findings_table",
    "incidents_table",
    "decisions_table",
    "approval_decisions_table",
    "idempotency_table",
    "remediation_audit_table",
    "event_bus",
    "dlq_url",
    "evidence_bucket",
    "state_machine_arn",
    "approval_api_url",
    "approval_user_pool_id",
    "approval_client_id",
    "guardduty_function",
    "securityhub_function",
    "cross_account_correlation",
    "scenario_timeout_seconds",
}
