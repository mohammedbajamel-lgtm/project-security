"""Normalize AWS Security Hub ASFF findings."""

from __future__ import annotations

import os
from typing import Any

import boto3
from common.logger import log_invocation

try:  # Flat imports support the standalone ingestion test/package layout.
    from normalizer import InvalidTelemetryError, base_finding, compact
except ModuleNotFoundError:  # Production package uses the repository root.
    from ingestion.normalizer import InvalidTelemetryError, base_finding, compact

ACCEPTED = {"MEDIUM", "HIGH", "CRITICAL"}


def normalize_asff(item: dict[str, Any], event: dict[str, Any]) -> dict[str, Any] | None:
    label = str(item.get("Severity", {}).get("Label", "")).upper()
    if label not in ACCEPTED:
        return None
    resources = item.get("Resources") or []
    resource_arn = resources[0].get("Id") if resources and isinstance(resources[0], dict) else None
    finding = base_finding(
        source="securityhub",
        finding_id=item.get("Id"),
        account=item.get("AwsAccountId") or event.get("account"),
        region=item.get("Region") or event.get("region"),
        event_time=item.get("UpdatedAt") or item.get("CreatedAt"),
        severity=label,
    )
    finding["ingested_at"] = finding["updated_at"]
    finding.update(
        {
            "resource_arn": resource_arn,
            "service": item.get("ProductName"),
            "details": compact({"types": item.get("Types", []), "title": item.get("Title")}),
        }
    )
    return {key: value for key, value in finding.items() if value is not None}


def normalize(event: dict[str, Any]) -> list[dict[str, Any]]:
    detail = event.get("detail")
    findings = detail.get("findings") if isinstance(detail, dict) else None
    if not isinstance(findings, list):
        raise InvalidTelemetryError("missing or invalid detail.findings")
    normalized = [normalize_asff(item, event) for item in findings if isinstance(item, dict)]
    return [item for item in normalized if item is not None]


@log_invocation("securityhub-ingestor")
def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    try:
        from telemetry_runtime import deliver
    except ModuleNotFoundError:
        from ingestion.telemetry_runtime import deliver

    return deliver(event, normalize, boto3_module=boto3, env=os.environ, deduplicate=True)
