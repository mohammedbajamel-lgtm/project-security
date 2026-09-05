import pytest

from tests.e2e.lifecycle_model import LifecycleModel

pytestmark = pytest.mark.e2e


@pytest.mark.parametrize(
    ("failure", "metric"),
    [
        ("unknown_evidence_id", "CitationValidationError"),
        ("hallucinated_principal", "HallucinationDetected"),
        ("quote_mismatch", "CitationValidationError"),
        ("empty_citations", "CitationValidationError"),
    ],
)
def test_insufficient_evidence_is_rejected_without_remediation(failure, metric):
    model = LifecycleModel()
    incident = model.incident(f"incident-{failure}", "finding")
    report = {"validation_status": "REJECTED", "validation_errors": [failure]}
    decision = model.reject(incident["incident_id"], "investigation_rejected")
    model.metrics.append(metric)
    assert report["validation_status"] == "REJECTED" and decision["level"] == 3
    assert metric in model.metrics and not model.executions and not model.state_changes
    assert (
        incident["status"] == "ESCALATED"
        and incident["escalation_reason"] == "safety_validation_failed"
    )
