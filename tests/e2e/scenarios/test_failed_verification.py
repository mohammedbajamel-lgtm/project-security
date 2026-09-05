import pytest

from tests.e2e.lifecycle_model import LifecycleModel

pytestmark = pytest.mark.e2e


@pytest.mark.parametrize(
    "failure", ["finding_still_active", "new_finding_detected", "containment_not_confirmed"]
)
def test_verification_failure_can_never_resolve(failure):
    model = LifecycleModel()
    incident = model.incident(f"incident-{failure}", "finding")
    incident["status"] = "VERIFYING"
    model.escalate(incident["incident_id"], "verification_failed", [failure])
    model.events.append("IncidentReportGenerated")
    model.preserve(
        incident["incident_id"], "verification.json", "incident-report.json", "manifest.json"
    )
    assert incident["status"] == "ESCALATED" and incident["status"] != "RESOLVED"
    assert incident["verification_failures"] == [failure]
    assert model.notifications and "IncidentEscalated" in model.events and model.evidence
