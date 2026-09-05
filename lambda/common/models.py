"""Typed models corresponding to the canonical Phase Two event schemas."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Severity = Literal["P1", "P2", "P3", "P4"]
Status = Literal["OPEN", "INVESTIGATING", "REMEDIATING", "VERIFYING", "RESOLVED", "ESCALATED"]


@dataclass(frozen=True, kw_only=True)
class BaseEvent:
    schema_version: str
    event_id: str
    timestamp: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, kw_only=True)
class FindingIngested(BaseEvent):
    event_type: Literal["FindingIngested"] = "FindingIngested"
    source_account: str
    source_region: str
    source_type: str
    finding_id: str
    finding_time: str
    severity: Severity
    principal_arn: str | None = None
    resource_arn: str | None = None
    source_ip: str | None = None
    service: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, kw_only=True)
class IncidentCreated(BaseEvent):
    event_type: Literal["IncidentCreated"] = "IncidentCreated"
    source_account: str
    source_region: str
    incident_id: str
    severity: Severity
    status: Literal["OPEN"]
    finding_ids: list[str]
    correlation_type: str
    created_at: str


@dataclass(frozen=True, kw_only=True)
class IncidentStatusChanged(BaseEvent):
    event_type: Literal["IncidentStatusChanged"] = "IncidentStatusChanged"
    incident_id: str
    previous_status: Status
    new_status: Status
    reason: str
    changed_at: str
    changed_by: str | None = None


@dataclass(frozen=True, kw_only=True)
class InvestigationStarted(BaseEvent):
    event_type: Literal["InvestigationStarted"] = "InvestigationStarted"
    incident_id: str
    started_at: str
    model: str
    run_id: str | None = None


@dataclass(frozen=True, kw_only=True)
class InvestigationCompleted(BaseEvent):
    event_type: Literal["InvestigationCompleted"] = "InvestigationCompleted"
    incident_id: str
    run_id: str
    completed_at: str
    recommendations: list[dict[str, Any]] = field(default_factory=list)
    confidence: float | None = None


@dataclass(frozen=True, kw_only=True)
class InvestigationFailed(BaseEvent):
    event_type: Literal["InvestigationFailed"] = "InvestigationFailed"
    incident_id: str
    run_id: str
    failed_at: str
    error_code: str
    error_message: str | None = None


@dataclass(frozen=True, kw_only=True)
class RemediationExecuted(BaseEvent):
    event_type: Literal["RemediationExecuted"] = "RemediationExecuted"
    incident_id: str
    run_id: str
    playbook_name: str
    executed_at: str
    steps: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True, kw_only=True)
class RemediationVerified(BaseEvent):
    event_type: Literal["RemediationVerified"] = "RemediationVerified"
    incident_id: str
    run_id: str
    verified_at: str
    checks_passed: int = 0
    checks_failed: int = 0


@dataclass(frozen=True, kw_only=True)
class RemediationFailed(BaseEvent):
    event_type: Literal["RemediationFailed"] = "RemediationFailed"
    incident_id: str
    run_id: str
    failed_at: str
    error_code: str
    error_message: str | None = None
