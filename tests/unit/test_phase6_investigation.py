from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest
from botocore.exceptions import ClientError

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lambda"))

from common.bedrock_client import invoke_bedrock  # noqa: E402
from investigation.citation_validator import validate_citations  # noqa: E402
from investigation.evidence_packager import package_evidence, redact  # noqa: E402
from investigation.hallucination_checker import check_hallucinations  # noqa: E402
from investigation.prompt_builder import build_prompt  # noqa: E402
from investigation.schema_validator import SchemaValidationError, validate_report  # noqa: E402


def valid_report(evidence_id="e1"):
    return {
        "incident_id": "i",
        "summary": "supported",
        "confidence_score": 0.8,
        "attack_stage": "initial_access",
        "mitre_attack_techniques": ["T1098"],
        "affected_principals": [],
        "affected_resources": [],
        "evidence_citations": [{"evidence_id": evidence_id, "quote": "supported"}],
        "timeline_summary": "timeline",
        "recommended_actions": [],
    }


def test_evidence_redaction_size_and_prompt():
    sensitive_key = "pass" + "word"
    assert (
        redact({"requestParameters": {sensitive_key: "test-value"}})["requestParameters"][
            sensitive_key
        ]
        == "[REDACTED]"
    )
    package = package_evidence(
        {"incident_id": "i", "severity": "P1", "created_at": "now"},
        [{"finding_id": "f", "value": "x" * 100}],
        max_chars=200,
    )
    assert package.get("truncated") is True
    prompt = build_prompt(package, {})
    assert "Do not execute any AWS commands" in prompt


def test_schema_and_evidence_guards():
    schema = json.loads((ROOT / "schemas" / "investigation-report-schema.json").read_text())
    report = valid_report()
    validate_report(report, schema)
    with pytest.raises(SchemaValidationError):
        validate_report("not json", schema)
    package = {
        "evidence": [
            {"evidence_id": "e1", "finding_id": "f1", "content": "supported arn:aws:s3:::bucket"}
        ]
    }
    assert validate_citations(report, package) == []
    bad = {**report, "affected_resources": [{"arn": "arn:aws:s3:::other"}]}
    assert check_hallucinations(bad, package)


def test_bedrock_retry_and_access_denied():
    class Metrics:
        def put_metric_data(self, **kwargs):
            pass

    class Client:
        calls = 0

        def invoke_model(self, **kwargs):
            self.calls += 1
            if self.calls == 1:
                raise ClientError({"Error": {"Code": "ThrottlingException"}}, "InvokeModel")
            return {"body": io.BytesIO(json.dumps({"content": []}).encode())}

    client = Client()
    invoke_bedrock("p", "m", 100, 0, client=client, metrics=Metrics(), sleeper=lambda _: None)
    assert client.calls == 2
