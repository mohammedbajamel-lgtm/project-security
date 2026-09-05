import pytest

from tests.e2e.lifecycle_model import LifecycleModel

pytestmark = pytest.mark.e2e


@pytest.mark.parametrize(
    "response_kind", ["non_json", "missing_fields", "invalid_enum", "all_retries_exhausted"]
)
def test_malformed_bedrock_retries_three_times_then_fails_closed(response_kind):
    model = LifecycleModel()
    incident = model.incident(f"incident-{response_kind}", "finding")
    incident["status"] = "INVESTIGATING"
    retries = [{"retry_reason": response_kind, "attempt": attempt} for attempt in range(1, 4)]
    model.audit.extend(retries)
    model.metrics.extend(["BedrockRetryCount"] * 3 + ["BedrockFinalFailure"])
    model.events.append("InvestigationFailed")
    model.escalate(incident["incident_id"], "investigation_failed")
    model.preserve(incident["incident_id"], "failure.json", "manifest.json")
    assert len(retries) == 3 and all("retry_reason" in entry for entry in retries)
    assert "BedrockFinalFailure" in model.metrics and "InvestigationFailed" in model.events
    assert incident["status"] == "ESCALATED" and not model.executions
