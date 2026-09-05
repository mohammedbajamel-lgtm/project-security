import pytest

from tests.e2e.lifecycle_model import LifecycleModel

pytestmark = pytest.mark.e2e


@pytest.mark.parametrize(
    "failure",
    [
        "ThrottlingException",
        "ServiceUnavailableException",
        "SocketTimeout",
        "ProvisionedThroughputExceededException",
    ],
)
def test_transient_failures_use_bounded_backoff_and_preserve_state(failure):
    model = LifecycleModel()
    incident = model.incident(f"incident-{failure}", "finding")
    backoffs = [1, 2, 4]
    model.audit.extend({"failure": failure, "backoff": delay} for delay in backoffs)
    model.metrics.extend(["BedrockRetryCount"] * 3)
    assert backoffs == [1, 2, 4]
    assert incident["status"] == "INVESTIGATING"
    assert incident["incident_id"] in model.incidents
    assert model.metrics.count("BedrockRetryCount") == 3 and not model.state_changes
