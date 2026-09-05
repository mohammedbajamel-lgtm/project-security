import sys
from pathlib import Path
from unittest.mock import Mock

import pytest
from botocore.exceptions import ClientError

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lambda"))
from knowledge_base.kb_ingestor import build_record, ingest_resolved_incident  # noqa: E402
from knowledge_base.kb_query import format_knowledge_context, query_knowledge_base  # noqa: E402
from knowledge_base.redactor import (  # noqa: E402
    RedactionError,
    redact_evidence,
    redact_for_bedrock,
    redact_incident_data,
)


def resolved():
    return {
        "incident_id": "inc-1",
        "status": "RESOLVED",
        "created_at": "2026-09-04T00:00:00Z",
        "reconstruction": {
            "attack_stages": ["Initial Access"],
            "mitre_techniques": ["T1078"],
            "timeline_summary": "arn:aws:iam::123456789012:user/test from 10.0.0.1",
        },
        "actions_taken": [{"action": "disable-key"}],
        "blast_radius_report": {"risk_score": 3},
        "investigation_report": {"root_cause_category": "credential-compromise"},
    }


def test_resolved_incident_is_ingested_and_sensitive_values_redacted():
    table = Mock()
    result = ingest_resolved_incident(resolved(), table)
    assert result["ingested"] is True
    assert "[REDACTED_ARN]" in result["record"]["timeline_pattern"]
    assert "[REDACTED_IP]" in result["record"]["timeline_pattern"]
    table.put_item.assert_called_once()


def test_escalated_incident_is_rejected():
    with pytest.raises(ValueError, match="only RESOLVED"):
        build_record(resolved() | {"status": "ESCALATED"})


def test_duplicate_incident_is_not_reingested():
    table = Mock()
    table.put_item.side_effect = ClientError(
        {"Error": {"Code": "ConditionalCheckFailedException", "Message": "duplicate"}},
        "PutItem",
    )
    assert ingest_resolved_incident(resolved(), table)["duplicate"] is True


@pytest.mark.parametrize(
    ("value", "marker"),
    [
        ("arn:aws:iam::123456789012:role/Admin", "[REDACTED_ARN]"),
        ("arn:aws:dynamodb:us-east-1:123456789012:table/test", "[REDACTED_TABLE]"),
        ("10.1.2.3", "[REDACTED_IP]"),
        ("2001:db8::1", "[REDACTED_IP]"),
        ("account 123456789012", "[REDACTED_ACCOUNT]"),
        ("AKIAABCDEFGHIJKLMNOP", "[REDACTED_KEY]"),
        ("password=supersecret", "[REDACTED_SECRET]"),
        ("owner@example.com", "[REDACTED_EMAIL]"),
        ("s3://private-bucket/object", "[REDACTED_S3_URL]"),
    ],
)
def test_redaction_patterns(value, marker):
    assert marker in redact_for_bedrock(value)


def test_nested_redaction_and_normal_text():
    value = {"items": ["normal text", {"source": "192.0.2.1"}]}
    assert redact_incident_data(value) == {"items": ["normal text", {"source": "[REDACTED_IP]"}]}
    assert redact_evidence("ordinary security event") == "ordinary security event"


def test_redaction_fails_closed_for_unsupported_data():
    with pytest.raises(RedactionError):
        redact_incident_data({"unsafe": object()})


def test_query_deduplicates_scores_limits_and_redacts():
    match = build_record(resolved())
    match["timeline_pattern"] = "contact owner@example.com"
    weaker = match | {"incident_id": "inc-2", "root_cause_category": "other"}
    table = Mock()
    table.query.side_effect = [{"Items": [weaker, match]}, {"Items": [match]}]
    results = query_knowledge_base(resolved(), table)
    assert [item["incident_id"] for item in results] == ["inc-1", "inc-2"]
    assert "[REDACTED_EMAIL]" in results[0]["timeline_pattern"]
    assert table.query.call_count == 2
    assert all(call.kwargs["Limit"] == 5 for call in table.query.call_args_list)
    assert format_knowledge_context(results).startswith("Previous Incident:")


def test_empty_knowledge_base_omits_context():
    table = Mock()
    table.query.return_value = {"Items": []}
    assert query_knowledge_base(resolved(), table) == []
    assert format_knowledge_context([]) == ""
