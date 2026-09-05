"""Normalize CloudTrail records from gzip objects."""

from __future__ import annotations

from typing import Any

from normalizer import base_finding, compact, stable_id


def normalize_record(record: dict[str, Any]) -> dict[str, Any]:
    identity = record.get("userIdentity") or {}
    resources = record.get("resources") or []
    event_time = record.get("eventTime")
    finding = base_finding(
        source="cloudtrail",
        finding_id=stable_id("cloudtrail", record.get("eventID"), event_time),
        account=record.get("recipientAccountId"),
        region=record.get("awsRegion"),
        event_time=event_time,
        severity="LOW",
    )
    # CloudTrail event IDs are immutable, so use the event timestamp as the
    # deterministic sort-key timestamp when the same log object is replayed.
    if event_time:
        finding["ingested_at"] = event_time
    finding.update(
        {
            "event_id": record.get("eventID"),
            "event_name": record.get("eventName"),
            "service": record.get("eventSource"),
            "principal_arn": identity.get("arn"),
            "source_ip": record.get("sourceIPAddress"),
            "resource_arn": resources[0].get("ARN") if resources else None,
            "details": compact(
                {
                    "error_code": record.get("errorCode"),
                    "resources": resources,
                    "read_only": record.get("readOnly"),
                }
            ),
        }
    )
    return {key: value for key, value in finding.items() if value is not None}


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, int]:
    from cloudtrail_s3_runtime import process_notifications

    return process_notifications(event)
