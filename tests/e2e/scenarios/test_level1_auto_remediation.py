import pytest

from tests.e2e.lifecycle_model import LifecycleModel
from tests.e2e.test_config import INCIDENT_TYPES

pytestmark = pytest.mark.e2e


@pytest.mark.parametrize("incident_type", INCIDENT_TYPES)
def test_all_six_incident_types_have_a_safe_lifecycle(incident_type):
    model = LifecycleModel()
    finding = f"e2e-{incident_type}"
    assert model.ingest(finding, incident_type=incident_type)
    assert model.incident(f"inc-{incident_type}", finding)["status"] == "INVESTIGATING"


def test_public_s3_level1_complete_success_path():
    model = LifecycleModel()
    assert model.ingest("finding-s3", resource="cloudsec-lab-e2e-bucket")
    incident = model.incident("incident-s3", "finding-s3")
    incident.update(
        validation_status="APPROVED", safety_level=1, report_json=True, report_markdown=True
    )
    model.executions.append({"incident_id": "incident-s3", "status": "SUCCEEDED"})
    model.state_changes.append("s3_public_access_block_enabled")
    model.preserve(
        "incident-s3",
        "config-snapshot.json",
        "remediation-history.json",
        "investigation-report.json",
        "manifest.json",
    )
    model.resolve("incident-s3")
    assert incident["status"] == "RESOLVED"
    assert incident["validation_status"] == "APPROVED" and incident["safety_level"] == 1
    assert model.executions == [{"incident_id": "incident-s3", "status": "SUCCEEDED"}]
    assert "s3_public_access_block_enabled" in model.state_changes
    assert len(model.evidence) == 4 and {
        "FindingIngested",
        "EvidencePreserved",
        "IncidentResolved",
    } <= set(model.metrics)
