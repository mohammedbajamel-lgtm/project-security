"""Merge correlation groups and construct deterministic incidents."""

from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import asdict
from typing import Any

from .tie_breaker import PRIORITY
from .time_window import timestamp

TYPE_PRIORITY = {"principal_arn": 0, "resource_arn": 1, "source_ip": 2}


def assign_findings(groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    assigned: set[str] = set()
    result = []
    for group in sorted(
        groups, key=lambda g: (TYPE_PRIORITY[g["correlation_type"]], -len(g["findings"]))
    ):
        findings = [f for f in group["findings"] if f.finding_id not in assigned]
        if len(findings) < 2:
            continue
        assigned.update(f.finding_id for f in findings)
        result.append({**group, "findings": findings})
    return result


def build_incident(group: dict[str, Any]) -> dict[str, Any]:
    findings = sorted(group["findings"], key=lambda f: f.finding_id)
    ids = [finding.finding_id for finding in findings]
    digest = hashlib.sha256("\n".join(ids).encode()).hexdigest()[:32]
    times = [timestamp(finding) for finding in findings]
    severity = min((f.severity for f in findings), key=lambda value: PRIORITY.get(value, 9))
    return {
        "incident_id": f"inc-{digest}",
        "findings": ids,
        "finding_records": [asdict(finding) for finding in findings],
        "severity": severity,
        "correlation_type": group["correlation_type"],
        "window_start": min(times).isoformat().replace("+00:00", "Z"),
        "window_end": max(times).isoformat().replace("+00:00", "Z"),
        "severity_distribution": dict(Counter(f.severity for f in findings)),
        "finding_count": len(findings),
        "source_account": findings[0].source_account,
        "source_region": findings[0].source_region,
    }
