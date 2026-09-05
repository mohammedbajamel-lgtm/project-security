"""Correlation orchestration and incident persistence."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from .config import load_config
from .incident_builder import assign_findings, build_incident
from .ip_correlator import correlate_by_ip
from .principal_correlator import correlate_by_principal
from .resource_correlator import correlate_by_resource


def correlate_findings(findings, *, windows=None, cross_account=False):
    windows = windows or load_config()
    groups = correlate_by_principal(findings, windows["principal"], cross_account)
    groups += correlate_by_ip(findings, windows["ip"])
    groups += correlate_by_resource(findings, windows["resource"])
    return [build_incident(group) for group in assign_findings(groups)]


def persist_incidents(
    incidents: list[dict[str, Any]], repository: Any, events: Any, bus_name: str
) -> list[dict[str, Any]]:
    results = []
    for incident in incidents:
        stored = repository.create_incident(
            **{
                key: incident[key]
                for key in (
                    "incident_id",
                    "findings",
                    "severity",
                    "correlation_type",
                    "window_start",
                    "window_end",
                )
            },
            idempotency_key=incident["incident_id"],
        )
        detail = {
            **incident,
            "event_type": "IncidentCreated",
            "status": "OPEN",
            "created_at": stored["created_at"],
            "event_time": stored["event_time"],
            "event_id": incident["incident_id"],
            "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "schema_version": "1.0.0",
            "finding_ids": incident["findings"],
        }
        response = events.put_events(
            Entries=[
                {
                    "Source": "cloudsec.correlation",
                    "DetailType": "IncidentCreated",
                    "EventBusName": bus_name,
                    "Detail": json.dumps(detail),
                }
            ]
        )
        if response.get("FailedEntryCount", 0):
            raise RuntimeError("IncidentCreated publication failed")
        results.append(stored)
    return results
