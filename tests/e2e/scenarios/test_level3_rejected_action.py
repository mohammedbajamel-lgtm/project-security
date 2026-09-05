import pytest
from safety.execution_engine import execute_validation

from tests.e2e.lifecycle_model import LifecycleModel

pytestmark = pytest.mark.e2e


@pytest.mark.parametrize(
    ("recommendation", "report", "reason"),
    [
        (
            {"action": "delete_all_buckets", "params": {}, "confidence": 1, "rationale": "bad"},
            {"incident_id": "i", "finding_type": "PublicS3Bucket"},
            "schema_invalid",
        ),
        (
            {
                "action": "block_s3_public_access",
                "params": {"bucket_name": "not-in-evidence"},
                "confidence": 1,
                "rationale": "bad",
            },
            {
                "incident_id": "i",
                "finding_type": "PublicS3Bucket",
                "affected_resources": [],
                "evidence_citations": [],
            },
            "evidence_invalid",
        ),
        (
            {
                "action": "block_s3_public_access",
                "params": {"bucket_name": "cloudsec-lab-b"},
                "confidence": 1,
                "rationale": "bad",
            },
            {
                "incident_id": "i",
                "finding_type": "CompromisedEC2",
                "affected_resources": [{"arn": "cloudsec-lab-b"}],
                "evidence_citations": [],
            },
            "policy_invalid",
        ),
    ],
)
def test_unsafe_recommendations_are_level3_and_never_execute(recommendation, report, reason):
    decision = execute_validation(recommendation, report)
    model = LifecycleModel()
    model.incident("i", "f")
    recorded = model.reject("i", decision["reason"])
    assert decision["level"] == recorded["level"] == 3 and decision["reason"] == reason
    assert decision["event_type"] == "RemediationRejected"
    assert not model.executions and not model.state_changes
    assert model.incidents["i"]["status"] == "ESCALATED"
    assert model.audit[-1]["result"] == "REJECTED" and model.evidence
