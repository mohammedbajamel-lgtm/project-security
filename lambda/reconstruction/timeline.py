"""Phase 7 chronological timeline construction."""

from __future__ import annotations

from datetime import UTC, datetime
from itertools import pairwise
from typing import Any


def _timestamp(item: dict[str, Any]) -> datetime:
    raw = item.get("event_time") or item.get("timestamp") or item.get("created_at")
    return (
        datetime.fromisoformat(str(raw).replace("Z", "+00:00")).astimezone(UTC)
        if raw
        else datetime.min.replace(tzinfo=UTC)
    )


def build_timeline(findings: list[dict[str, Any]]) -> dict[str, Any]:
    seen, ordered = set(), []
    for finding in sorted(
        findings, key=lambda item: (_timestamp(item), item.get("finding_id", ""))
    ):
        identity = str(finding.get("finding_id") or finding.get("event_id") or finding)
        if identity in seen:
            continue
        seen.add(identity)
        ordered.append(
            {
                "event_time": _timestamp(finding).isoformat().replace("+00:00", "Z"),
                "event_type": finding.get("finding_type", "unknown"),
                "event_name": finding.get("action") or finding.get("event_name") or "unknown",
                "evidence_id": finding.get("evidence_id", identity),
                "finding_id": finding.get("finding_id", identity),
                "principal_arn": finding.get("principal_arn"),
                "resource_arn": finding.get("resource_arn"),
                "source_account": finding.get("account_id") or finding.get("source_account"),
                "region": finding.get("region"),
                "source_ip": finding.get("source_ip"),
                "severity": finding.get("severity", "UNKNOWN"),
            }
        )
    gaps = []
    for previous, current in pairwise(ordered):
        elapsed = _timestamp(current) - _timestamp(previous)
        if elapsed.total_seconds() > 3600:
            gaps.append(
                {
                    "start": previous["event_time"],
                    "end": current["event_time"],
                    "duration_minutes": int(elapsed.total_seconds() / 60),
                }
            )
    original_count = len(ordered)
    return {
        "events": ordered if original_count <= 200 else ordered[:100] + ordered[-100:],
        "gap_analysis": gaps,
        "original_event_count": original_count,
    }
