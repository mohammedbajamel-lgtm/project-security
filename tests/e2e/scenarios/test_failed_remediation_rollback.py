import pytest
from remediation.failure_handler import handle_failure

from tests.e2e.lifecycle_model import LifecycleModel

pytestmark = pytest.mark.e2e


@pytest.mark.parametrize(
    "action",
    ["disable_iam_key", "block_s3_public_access", "isolate_ec2_instance"],
)
def test_failed_remediation_rolls_back_and_escalates(action):
    model = LifecycleModel()
    incident = model.incident(f"incident-{action}", "finding")
    handlers = {
        "enable_iam_key": lambda state: state,
        "revert_s3_public_access_block": lambda state: state,
        "attach_original_security_groups": lambda state: state,
    }
    result = handle_failure(action, {"restored": True}, handlers)
    model.audit.append({"action": action, "rollback": result["status"]})
    model.events.append("RemediationFailed")
    model.escalate(incident["incident_id"], "remediation_failed")
    model.preserve(
        incident["incident_id"], "pre-remediation-config.json", "failure.json", "manifest.json"
    )
    assert result["status"] == "ROLLED_BACK" and result["result"]["restored"]
    assert incident["status"] == "ESCALATED" and model.notifications
    assert "RemediationFailed" in model.events and len(model.evidence) == 3
