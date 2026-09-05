"""Deterministic anomaly scoring against a principal baseline."""

from __future__ import annotations

from datetime import datetime
from typing import Any


def detect_anomalies(finding: dict[str, Any], baseline: dict[str, Any] | None) -> dict[str, Any]:
    if baseline is None:
        return {
            "anomaly_score": 0.5,
            "anomaly_reasons": ["new_principal"],
            "baseline_confidence": 0.0,
        }
    confidence = float(baseline.get("confidence_score", 0))
    if confidence < 0.5:
        return {
            "anomaly_score": None,
            "anomaly_reasons": ["insufficient_baseline_data"],
            "baseline_confidence": confidence,
        }
    score, reasons = 0.0, []
    signals = [
        (finding.get("source_region") not in baseline.get("normal_regions", []), 0.3, "new_region"),
        (
            finding.get("api_call") not in baseline.get("common_api_calls", {}),
            0.2,
            "uncommon_api_call",
        ),
        (
            finding.get("assumed_role")
            and finding.get("assumed_role") not in baseline.get("common_assumed_roles", []),
            0.3,
            "new_assumed_role",
        ),
    ]
    raw_time = finding.get("finding_time") or finding.get("ingested_at")
    if raw_time:
        hour = datetime.fromisoformat(raw_time.replace("Z", "+00:00")).hour
        hours = baseline.get("typical_hours", [])
        outside = bool(hours) and all(min((hour - h) % 24, (h - hour) % 24) > 2 for h in hours)
        signals.append((outside, 0.2, "outside_typical_hours"))
    for active, weight, reason in signals:
        if active:
            score += weight
            reasons.append(reason)
    return {
        "anomaly_score": min(score, 1.0),
        "anomaly_reasons": reasons,
        "baseline_confidence": confidence,
    }
