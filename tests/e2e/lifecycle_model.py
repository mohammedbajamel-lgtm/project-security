"""Deterministic lifecycle model used to prove fail-closed E2E invariants."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class LifecycleModel:
    findings: dict = field(default_factory=dict)
    incidents: dict = field(default_factory=dict)
    locks: set = field(default_factory=set)
    events: list = field(default_factory=list)
    metrics: list = field(default_factory=list)
    audit: list = field(default_factory=list)
    evidence: list = field(default_factory=list)
    notifications: list = field(default_factory=list)
    state_changes: list = field(default_factory=list)
    executions: list = field(default_factory=list)

    def ingest(self, finding_id: str, **fields) -> bool:
        if finding_id in self.findings:
            return False
        self.findings[finding_id] = {"finding_id": finding_id, **fields}
        self.metrics.append("FindingIngested")
        return True

    def incident(self, incident_id: str, finding_id: str, status: str = "INVESTIGATING"):
        if incident_id not in self.incidents:
            self.incidents[incident_id] = {
                "incident_id": incident_id,
                "finding_id": finding_id,
                "status": status,
            }
            self.events.append("IncidentCreated")
        return self.incidents[incident_id]

    def preserve(self, incident_id: str, *artifacts: str) -> None:
        self.evidence.extend(f"{incident_id}/{name}" for name in artifacts)
        self.metrics.append("EvidencePreserved")

    def resolve(self, incident_id: str) -> None:
        self.incidents[incident_id]["status"] = "RESOLVED"
        self.events.append("IncidentResolved")
        self.metrics.append("IncidentResolved")

    def escalate(self, incident_id: str, reason: str, failures=None) -> None:
        item = self.incidents[incident_id]
        item.update(status="ESCALATED", escalation_reason=reason)
        if failures:
            item["verification_failures"] = list(failures)
        self.events.append("IncidentEscalated")
        self.notifications.append({"incident_id": incident_id, "reason": reason})
        self.metrics.append("IncidentEscalated")

    def reject(self, incident_id: str, reason: str) -> dict:
        decision = {"level": 3, "reason": reason, "event_type": "RemediationRejected"}
        self.events.append("RemediationRejected")
        self.audit.append({"incident_id": incident_id, "result": "REJECTED", "reason": reason})
        self.escalate(incident_id, "safety_validation_failed")
        self.preserve(incident_id, "investigation-report.json", "manifest.json")
        return decision

    def acquire(self, key: str) -> bool:
        if key in self.locks:
            return False
        self.locks.add(key)
        return True

    def release(self, key: str) -> None:
        self.locks.discard(key)
