"""Pure normalization helpers for untrusted AWS telemetry."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any


class InvalidTelemetryError(ValueError):
    """Raised when an external event cannot be safely normalized."""


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InvalidTelemetryError(f"missing or invalid {field}")
    return value


def severity_to_priority(value: Any) -> str:
    if isinstance(value, dict):
        value = value.get("Label") or value.get("Normalized")
    if isinstance(value, str):
        label = value.upper()
        if label in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"}:
            return {"CRITICAL": "P1", "HIGH": "P2", "MEDIUM": "P3"}.get(label, "P4")
        try:
            value = float(value)
        except ValueError as exc:
            raise InvalidTelemetryError("invalid severity") from exc
    if isinstance(value, int | float):
        return "P1" if value >= 7 else "P2" if value >= 4 else "P3" if value >= 1 else "P4"
    raise InvalidTelemetryError("missing or invalid severity")


def stable_id(source: str, *parts: Any) -> str:
    material = json.dumps([source, *parts], sort_keys=True, default=str).encode()
    return f"{source}-{sha256(material).hexdigest()}"


def base_finding(
    *,
    source: str,
    finding_id: str,
    account: str,
    region: str,
    event_time: str,
    severity: Any,
    received_at: str | None = None,
) -> dict[str, Any]:
    return {
        "finding_id": require_text(finding_id, "finding_id"),
        "ingested_at": received_at or utc_now(),
        "updated_at": require_text(event_time, "event_time"),
        "source_account": require_text(account, "source_account"),
        "source_region": require_text(region, "source_region"),
        "source_type": source,
        "severity": severity_to_priority(severity),
    }


def compact(value: Any, *, limit: int = 32_000) -> Any:
    """Bound potentially sensitive or oversized structures before persistence."""
    encoded = json.dumps(value, default=str, separators=(",", ":"))
    if len(encoded.encode()) <= limit:
        return value
    return {"truncated": True, "sha256": sha256(encoded.encode()).hexdigest()}
