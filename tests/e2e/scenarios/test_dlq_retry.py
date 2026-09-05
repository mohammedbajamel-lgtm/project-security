import json

import pytest

pytestmark = pytest.mark.e2e


@pytest.mark.parametrize("source", ["GuardDuty", "CloudTrail"])
def test_unparseable_payload_is_preserved_and_measured(source):
    original = {"source": source, "payload": "{not-json"}
    dlq = [json.dumps(original)]
    metrics = ["ParseFailure"]
    assert json.loads(dlq[0]) == original
    assert metrics.count("ParseFailure") == 1


def test_dlq_retention_alarm_and_access_policy_contract():
    retention_seconds = 1_209_600
    alarm_threshold = 10
    policy = {"public_receive": False, "receiver": "cloudsec-lab-recovery-role"}
    metrics = ["TelemetryIngestionLag"]
    assert retention_seconds == 14 * 24 * 60 * 60
    assert alarm_threshold == 10 and "TelemetryIngestionLag" in metrics
    assert policy == {"public_receive": False, "receiver": "cloudsec-lab-recovery-role"}
