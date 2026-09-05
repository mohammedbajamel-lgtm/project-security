"""Normalize GuardDuty findings and deliver them to CloudSec."""

from __future__ import annotations

import os
from typing import Any

import boto3
from common.logger import log_invocation

try:  # Flat imports support the standalone ingestion test/package layout.
    from normalizer import InvalidTelemetryError, base_finding, compact
except ModuleNotFoundError:  # Production package uses the repository root.
    from ingestion.normalizer import InvalidTelemetryError, base_finding, compact


def normalize(event: dict[str, Any]) -> dict[str, Any]:
    detail = event.get("detail")
    if not isinstance(detail, dict):
        raise InvalidTelemetryError("missing or invalid detail")
    service = detail.get("service") if isinstance(detail.get("service"), dict) else {}
    resource = detail.get("resource") if isinstance(detail.get("resource"), dict) else {}
    action = service.get("action", {}).get("awsApiCallAction", {})
    finding = base_finding(
        source="guardduty",
        finding_id=detail.get("id"),
        account=event.get("account"),
        region=event.get("region"),
        event_time=detail.get("updatedAt") or event.get("time"),
        severity=detail.get("severity"),
    )
    finding.update(
        {
            "event_id": event.get("id"),
            "service": service.get("serviceName", "guardduty"),
            "resource_arn": resource.get("resourceArn"),
            "principal_arn": resource.get("accessKeyDetails", {}).get("principalId"),
            "source_ip": action.get("remoteIpDetails", {}).get("ipAddressV4"),
            "details": compact({"type": detail.get("type"), "title": detail.get("title")}),
        }
    )
    return {key: value for key, value in finding.items() if value is not None}


@log_invocation("guardduty-ingestor")
def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    try:
        from telemetry_runtime import deliver
    except ModuleNotFoundError:
        from ingestion.telemetry_runtime import deliver

    return deliver(event, normalize, boto3_module=boto3, env=os.environ)
