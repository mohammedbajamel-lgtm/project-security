import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import Mock

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lambda"))
from reporting.executive_summary import generate_executive_summary  # noqa: E402
from reporting.json_report_generator import generate_json_report  # noqa: E402
from reporting.main import lambda_handler  # noqa: E402
from reporting.markdown_report_generator import generate_markdown_report  # noqa: E402


def incident():
    return {
        "incident_id": "inc-123",
        "severity": "HIGH",
        "status": "RESOLVED",
        "created_at": "2026-09-04T00:00:00Z",
        "detection_source": "GuardDuty",
        "business_impact": "one workload was isolated",
        "action_summary": "credential containment",
        "investigation_report": {
            "root_cause": "Compromised credential",
            "recommended_actions": ["Rotate credentials"],
        },
        "reconstruction": {
            "timeline": [
                {
                    "time": "00:00",
                    "event": "Login",
                    "attack_stage": "Initial Access",
                    "evidence_id": "ev-1",
                }
            ],
            "mitre_techniques": ["T1078"],
        },
        "actions_taken": [{"timestamp": "00:01", "action": "Disable key", "status": "OK"}],
    }


def test_json_report_full_and_missing_optional_sections():
    report = generate_json_report(incident(), generated_at=datetime(2026, 9, 4, tzinfo=UTC))
    assert report["root_cause"] == "Compromised credential"
    assert report["mitre_attack_techniques"] == ["T1078"]
    assert report["blast_radius"] == {}
    assert report["evidence"] == {}


def test_json_report_requires_identity_fields():
    with pytest.raises(ValueError, match="missing report fields"):
        generate_json_report({"incident_id": "inc-1"})


def test_markdown_contains_sections_and_tables():
    rendered = generate_markdown_report(generate_json_report(incident()))
    assert "# Incident Report: inc-123" in rendered
    assert "## Executive Summary" in rendered
    assert "| Time | Event | Attack Stage | Evidence ID |" in rendered
    assert "| 00:00 | Login | Initial Access | ev-1 |" in rendered
    assert "## Verification Results" in rendered


def test_executive_summary_has_safe_length_and_redacts_details():
    data = incident() | {
        "business_impact": "arn:aws:iam::123456789012:role/admin contacted 10.2.3.4",
        "recommendations": ["Disable AKIAABCDEFGHIJKLMNOP"],
    }
    summary = generate_executive_summary(data)
    assert 5 <= len([part for part in summary.split(". ") if part]) <= 10
    assert "arn:aws" not in summary
    assert "10.2.3.4" not in summary
    assert "AKIAABCDEFGHIJKLMNOP" not in summary
    assert "[REDACTED]" in summary


def test_executive_summary_handles_empty_incident():
    assert len(generate_executive_summary({}).split(". ")) >= 5


def test_handler_stores_both_reports_and_publishes(monkeypatch):
    monkeypatch.setenv("EVIDENCE_BUCKET_NAME", "evidence-bucket")
    monkeypatch.setenv("EVIDENCE_KEY_ARN", "arn:aws:kms:us-east-1:123:key/test")
    monkeypatch.setenv("REPORTS_TOPIC_ARN", "arn:aws:sns:us-east-1:123:reports")
    s3 = Mock()
    sns = Mock()

    result = lambda_handler(
        {"detail": {"incident": incident()}}, None, s3_client=s3, sns_client=sns
    )

    assert result["notified"] is True
    assert s3.put_object.call_count == 2
    keys = {call.kwargs["Key"] for call in s3.put_object.call_args_list}
    assert keys == {
        "evidence/inc-123/reports/incident_report.json",
        "evidence/inc-123/reports/incident_report.md",
    }
    json_call = next(
        call for call in s3.put_object.call_args_list if call.kwargs["Key"].endswith("json")
    )
    assert json.loads(json_call.kwargs["Body"])["incident_id"] == "inc-123"
    sns.publish.assert_called_once()
