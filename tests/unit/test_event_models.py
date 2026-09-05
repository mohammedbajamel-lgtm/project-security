"""Unit tests for the typed Phase 2 event models."""

from __future__ import annotations

import sys
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

LAMBDA_ROOT = Path(__file__).resolve().parents[2] / "lambda"
sys.path.insert(0, str(LAMBDA_ROOT))

from common.models import (  # noqa: E402
    FindingIngested,
    IncidentCreated,
    IncidentStatusChanged,
    InvestigationCompleted,
    InvestigationFailed,
    InvestigationStarted,
    RemediationExecuted,
    RemediationFailed,
    RemediationVerified,
)

BASE = {
    "schema_version": "1.0",
    "event_id": "event-1",
    "timestamp": "2026-09-04T00:00:00Z",
}


def test_all_phase2_event_models_serialize_with_defaults():
    events = [
        FindingIngested(
            **BASE,
            source_account="123456789012",
            source_region="us-east-1",
            source_type="guardduty",
            finding_id="finding-1",
            finding_time=BASE["timestamp"],
            severity="P2",
        ),
        IncidentCreated(
            **BASE,
            source_account="123456789012",
            source_region="us-east-1",
            incident_id="incident-1",
            severity="P2",
            status="OPEN",
            finding_ids=["finding-1"],
            correlation_type="principal",
            created_at=BASE["timestamp"],
        ),
        IncidentStatusChanged(
            **BASE,
            incident_id="incident-1",
            previous_status="OPEN",
            new_status="INVESTIGATING",
            reason="Investigation started",
            changed_at=BASE["timestamp"],
        ),
        InvestigationStarted(
            **BASE,
            incident_id="incident-1",
            started_at=BASE["timestamp"],
            model="test-model",
        ),
        InvestigationCompleted(
            **BASE,
            incident_id="incident-1",
            run_id="run-1",
            completed_at=BASE["timestamp"],
        ),
        InvestigationFailed(
            **BASE,
            incident_id="incident-1",
            run_id="run-1",
            failed_at=BASE["timestamp"],
            error_code="MODEL_ERROR",
        ),
        RemediationExecuted(
            **BASE,
            incident_id="incident-1",
            run_id="run-1",
            playbook_name="contain-principal",
            executed_at=BASE["timestamp"],
        ),
        RemediationVerified(
            **BASE,
            incident_id="incident-1",
            run_id="run-1",
            verified_at=BASE["timestamp"],
        ),
        RemediationFailed(
            **BASE,
            incident_id="incident-1",
            run_id="run-1",
            failed_at=BASE["timestamp"],
            error_code="STEP_FAILED",
        ),
    ]

    for event in events:
        serialized = event.to_dict()
        assert serialized["event_type"] == event.event_type
        assert serialized["schema_version"] == "1.0"

    assert events[0].details == {}
    assert events[4].recommendations == []
    assert events[6].steps == []
    assert events[7].checks_passed == 0
    assert events[7].checks_failed == 0


def test_phase2_event_models_are_immutable():
    event = InvestigationStarted(
        **BASE,
        incident_id="incident-1",
        started_at=BASE["timestamp"],
        model="test-model",
    )

    with pytest.raises(FrozenInstanceError):
        event.model = "changed"  # type: ignore[misc]
