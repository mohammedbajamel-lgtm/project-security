import pytest

from tests.e2e.lifecycle_model import LifecycleModel

pytestmark = pytest.mark.e2e


def _waiting_model():
    model = LifecycleModel()
    model.ingest("finding-key", key_status="Active")
    incident = model.incident("incident-key", "finding-key")
    incident.update(safety_level=2, status="WAITING_FOR_APPROVAL", decision_visible=True)
    return model, incident


def test_level2_waits_then_approval_disables_key_and_resolves():
    model, incident = _waiting_model()
    assert model.findings["finding-key"]["key_status"] == "Active"
    assert incident["decision_visible"] and not model.state_changes
    incident["approval"] = "APPROVED"
    model.state_changes.append("iam_key_disabled")
    model.preserve(
        "incident-key", "config-snapshot.json", "remediation-history.json", "manifest.json"
    )
    model.resolve("incident-key")
    assert incident["status"] == "RESOLVED" and "iam_key_disabled" in model.state_changes


def test_level2_rejection_never_disables_key_and_escalates():
    model, incident = _waiting_model()
    incident["approval"] = "REJECTED"
    model.escalate("incident-key", "approval_rejected")
    model.preserve("incident-key", "investigation-report.json", "manifest.json")
    assert incident["status"] == "ESCALATED"
    assert "iam_key_disabled" not in model.state_changes
