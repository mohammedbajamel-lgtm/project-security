import pytest

from tests.e2e.lifecycle_model import LifecycleModel

pytestmark = pytest.mark.e2e


def test_duplicate_finding_incident_correlation_and_execution_are_idempotent():
    model = LifecycleModel()
    assert model.ingest("finding-1") is True
    assert model.ingest("finding-1") is False
    first = model.incident("incident-1", "finding-1")
    second = model.incident("incident-1", "finding-1")
    assert first is second
    assert model.acquire("incident-1:remediate") is True
    model.executions.append("incident-1")
    assert model.acquire("incident-1:remediate") is False
    assert len(model.findings) == len(model.incidents) == len(model.executions) == 1
    assert model.events.count("IncidentCreated") == 1
    model.release("incident-1:remediate")
    assert not model.locks
