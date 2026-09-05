"""Evidence packaging with recursive secret redaction and size limits."""

from __future__ import annotations

import json
import uuid
from typing import Any

SENSITIVE = {"password", "accesskey", "secretkey", "token"}


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if key.lower() in SENSITIVE else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def package_evidence(
    incident: dict[str, Any],
    findings: list[dict[str, Any]],
    baselines: dict[str, Any] | None = None,
    reconstruction: dict[str, Any] | None = None,
    blast_radius: dict[str, Any] | None = None,
    max_chars: int = 16000,
) -> dict[str, Any]:
    evidence = []
    for finding in findings:
        content = redact(finding)
        evidence.append(
            {
                "evidence_id": str(uuid.uuid4()),
                "finding_id": finding["finding_id"],
                "content": content,
            }
        )
    result = {
        "incident_id": incident["incident_id"],
        "severity": incident["severity"],
        "created_at": incident["created_at"],
        "correlation": {
            key: incident.get(key)
            for key in ("correlation_type", "window_start", "window_end", "finding_count")
        },
        "evidence": evidence,
        "baselines": baselines or {},
        "reconstruction": reconstruction or {},
        "blast_radius": blast_radius or {},
    }
    while evidence and len(json.dumps(result, default=str)) > max_chars:
        evidence.pop()
        result["truncated"] = True
    result["evidence_count"] = len(evidence)
    return result
