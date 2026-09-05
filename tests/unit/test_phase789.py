from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lambda"))

from blast_radius.analyzer import analyze  # noqa: E402
from blast_radius.policy_simulator import simulate_permissions  # noqa: E402
from blast_radius.resource_classifier import classify_resource  # noqa: E402
from blast_radius.risk_scoring import score  # noqa: E402
from blast_radius.role_chain import find_assumable_roles  # noqa: E402
from blast_radius.static_analyzer import static_analyze  # noqa: E402
from reconstruction.attack_stages import classify_timeline  # noqa: E402
from reconstruction.cross_account import label  # noqa: E402
from reconstruction.mitre import map_techniques  # noqa: E402
from reconstruction.orchestrator import reconstruct_attack  # noqa: E402
from reconstruction.timeline import build_timeline  # noqa: E402
from safety.execution_engine import execute_validation  # noqa: E402
from safety.main import _dynamodb_item, _execution_evidence  # noqa: E402
from safety.policy import evaluate  # noqa: E402


def test_timeline_is_ordered_deduplicated_and_evidence_only():
    findings = [
        {"finding_id": "b", "event_time": "2026-01-01T02:00:00Z", "action": "GetObject"},
        {"finding_id": "a", "event_time": "2026-01-01T01:00:00Z", "action": "AssumeRole"},
        {"finding_id": "a", "event_time": "2026-01-01T01:00:00Z", "action": "AssumeRole"},
    ]
    timeline = build_timeline(findings)
    assert [event["finding_id"] for event in timeline["events"]] == ["a", "b"]
    assert [item["technique_id"] for item in map_techniques(timeline["events"])] == [
        "T1078.004",
        "T1530",
    ]


def test_blast_radius_is_bounded_and_risk_is_deterministic():
    findings = [
        {"principal_arn": "p", "resource_arn": f"r{i}", "account_id": "a", "region": "us-east-1"}
        for i in range(11)
    ]
    result = analyze(findings, max_resources=10)
    assert result["truncated"] is True
    assert len(result["affected_resources"]) == 10
    assert result["risk_level"] == "HIGH"


def test_safety_denies_unknown_low_confidence_and_rejected_investigation():
    decision = evaluate(
        {"action": "delete_everything", "confidence": 0.2, "rationale": ""},
        {"incident_id": "i", "investigation_status": "REJECTED"},
    )
    assert decision["decision"] == "DENIED"
    assert len(decision["reasons"]) == 4


def test_safety_approves_only_allowlisted_action_and_marks_l2_for_human():
    decision = evaluate(
        {"action": "disable_iam_key", "confidence": 0.95, "rationale": "cited evidence"},
        {"incident_id": "i", "investigation_status": "ACCEPTED"},
    )
    assert decision["decision"] == "APPROVED"
    assert decision["requires_human_approval"] is True


def test_phase9_checkpoint_levels_and_evidence_gate():
    daytime = datetime(2026, 9, 4, 12, tzinfo=UTC)
    base = {
        "incident_id": "i",
        "finding_type": "PublicS3Bucket",
        "affected_resources": [{"arn": "arn:aws:s3:::safe-bucket"}],
        "affected_principals": [],
        "evidence_citations": [],
    }
    level1 = execute_validation(
        {
            "action": "block_s3_public_access",
            "params": {"bucket_name": "safe-bucket"},
            "confidence": 0.9,
            "rationale": "public",
        },
        base,
        now=daytime,
    )
    assert level1["level"] == 1 and level1["event_type"] == "RemediationApproved"
    report2 = {
        **base,
        "finding_type": "UnauthorizedAccess",
        "affected_principals": [{"arn": "arn:aws:iam::1:user/alice"}],
        "evidence_citations": [{"quote": "AKIAEXAMPLE"}],
    }
    level2 = execute_validation(
        {
            "action": "disable_iam_key",
            "params": {"user_name": "alice", "access_key_id": "AKIAEXAMPLE"},
            "confidence": 0.9,
            "rationale": "compromised",
        },
        report2,
        now=daytime,
    )
    assert level2["level"] == 2 and level2["expires_at_epoch"] > 0
    rejected = execute_validation(
        {
            "action": "block_s3_public_access",
            "params": {"bucket_name": "invented"},
            "confidence": 0.9,
            "rationale": "bad",
        },
        base,
        now=daytime,
    )
    assert rejected["level"] == 3


def test_safety_decisions_convert_json_floats_for_dynamodb():
    stored = _dynamodb_item({"confidence": 0.9, "nested": [{"risk": 1.5}]})
    assert str(stored["confidence"]) == "0.9"
    assert str(stored["nested"][0]["risk"]) == "1.5"


def test_iam_execution_evidence_preserves_cloudtrail_confirmation():
    evidence = _execution_evidence(
        {"params": {"user_name": "lab-user", "access_key_id": "AKIAEXAMPLE"}},
        {
            "finding_type": "UnauthorizedAccess",
            "cloudtrail_used": True,
            "last_used": "2026-09-05T01:02:03Z",
        },
    )

    assert evidence == {
        "user_name": "lab-user",
        "access_key_id": "AKIAEXAMPLE",
        "compromised": True,
        "cloudtrail_used": True,
        "last_used": "2026-09-05T01:02:03Z",
    }


def test_reconstruction_gap_cross_account_stage_and_cap():
    findings = [
        {
            "finding_id": "1",
            "event_time": "2026-01-01T00:00:00Z",
            "action": "CreateAccessKey",
            "principal_arn": "arn:aws:iam::1:user/a",
            "resource_arn": "arn:aws:iam::2:role/b",
        },
        {"finding_id": "2", "event_time": "2026-01-01T02:00:00Z", "action": "StopLogging"},
    ]
    result = reconstruct_attack(findings)
    assert result["timeline_gaps"][0]["duration_minutes"] == 120
    assert result["cross_account_summary"] == ["1->2"]
    assert result["attack_stages_detected"] == ["privilege_escalation", "defense_evasion"]
    labeled, pairs = label(result["timeline"])
    assert labeled[0]["cross_account"] and pairs == ["1->2"]
    events, anomaly = classify_timeline(list(reversed(result["timeline"])))
    assert events and anomaly is True
    many = [
        {"finding_id": str(i), "event_time": f"2026-01-01T00:{i % 60:02}:00Z"} for i in range(201)
    ]
    assert len(build_timeline(many)["events"]) == 200


def test_blast_radius_helpers():
    assert classify_resource("arn:aws:kms:us-east-1:1:key/x")["level"] == "critical"
    assert classify_resource("arn:aws:s3:::backup-data")["level"] == "high"
    assert classify_resource("arn:aws:lambda:us-east-1:1:function:x")["level"] == "medium"
    static = static_analyze(
        [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:DeleteObject"],
                "Condition": {"StringEquals": {}},
            },
            {"Effect": "Deny", "Action": "s3:DeleteObject"},
        ]
    )
    assert static["explicitly_allowed"] == ["s3:GetObject"]
    graph = {"start": ["r1"], "r1": ["r2"], "r2": ["r1"]}
    assert find_assumable_roles("start", graph)["reachable_roles"] == ["r1", "r2"]
    risk = score([{"level": "critical"}] * 4, [{"privilege_level": "admin"}], ["a"] * 20)
    assert risk["risk_score"] == 10 and risk["risk_level"] == "CRITICAL"


def test_policy_simulator_classifies_and_caches():
    class IAM:
        calls = 0

        def simulate_principal_policy(self, **_kwargs):
            self.calls += 1
            return {
                "EvaluationResults": [
                    {"EvalActionName": "s3:GetObject", "EvalDecision": "allowed"},
                    {"EvalActionName": "iam:CreateUser", "EvalDecision": "explicitDeny"},
                    {"EvalActionName": "kms:Decrypt", "EvalDecision": "implicitDeny"},
                ]
            }

    iam = IAM()
    first = simulate_permissions(
        "arn:aws:iam::1:role/test",
        ["s3:GetObject", "iam:CreateUser", "kms:Decrypt"],
        iam=iam,
        now=lambda: 1,
    )
    second = simulate_permissions(
        "arn:aws:iam::1:role/test",
        ["s3:GetObject", "iam:CreateUser", "kms:Decrypt"],
        iam=iam,
        now=lambda: 2,
    )
    assert first["allowed_actions"] == ["s3:GetObject"]
    assert first["denied_actions"] == ["iam:CreateUser"]
    assert first["implicit_denied"] == ["kms:Decrypt"]
    assert second == first and iam.calls == 1
