"""Normalize AWS Config configuration-item change events."""

from __future__ import annotations

import os
from typing import Any

import boto3
from common.logger import log_invocation

try:  # Flat imports support the standalone ingestion test/package layout.
    from normalizer import InvalidTelemetryError, base_finding, compact, stable_id
except ModuleNotFoundError:  # Production package uses the repository root.
    from ingestion.normalizer import InvalidTelemetryError, base_finding, compact, stable_id


def normalize(event: dict[str, Any]) -> dict[str, Any]:
    detail = event.get("detail")
    item = detail.get("configurationItem") if isinstance(detail, dict) else None
    if not isinstance(item, dict) or "configuration" not in item:
        raise InvalidTelemetryError("missing configurationItem.configuration")
    captured = item.get("configurationItemCaptureTime") or event.get("time")
    finding = base_finding(
        source="aws_config",
        finding_id=stable_id("config", item.get("resourceType"), item.get("resourceId"), captured),
        account=item.get("awsAccountId") or event.get("account"),
        region=item.get("awsRegion") or event.get("region"),
        event_time=captured,
        severity="LOW",
    )
    finding.update(
        {
            "resource_arn": item.get("ARN"),
            "service": "config",
            "details": compact(
                {
                    "resource_type": item.get("resourceType"),
                    "resource_id": item.get("resourceId"),
                    "configuration": item.get("configuration"),
                    "tags": item.get("tags", {}),
                    "related_resources": item.get("relationships", []),
                }
            ),
        }
    )
    return {key: value for key, value in finding.items() if value is not None}


@log_invocation("config-ingestor")
def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    try:
        from telemetry_runtime import deliver
    except ModuleNotFoundError:
        from ingestion.telemetry_runtime import deliver

    return deliver(event, normalize, boto3_module=boto3, env=os.environ)
