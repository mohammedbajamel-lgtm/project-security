"""AWS delivery boundary shared by telemetry ingestion handlers."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from typing import Any

from boto3.dynamodb.types import TypeSerializer


def deliver(
    event: dict[str, Any],
    normalizer: Callable[[dict[str, Any]], Any],
    *,
    boto3_module: Any,
    env: Mapping[str, str],
    deduplicate: bool = False,
) -> dict[str, int]:
    required = ("FINDINGS_TABLE", "SECURITY_BUS_NAME", "DLQ_URL")
    if any(not env.get(key) for key in required):
        raise RuntimeError("telemetry runtime is not configured")
    dynamodb = boto3_module.client("dynamodb")
    events = boto3_module.client("events")
    sqs = boto3_module.client("sqs")
    cloudwatch = boto3_module.client("cloudwatch")
    try:
        normalized = normalizer(event)
        findings = normalized if isinstance(normalized, list) else [normalized]
        serializer = TypeSerializer()
        stored = 0
        for finding in findings:
            kwargs: dict[str, Any] = {
                "TableName": env["FINDINGS_TABLE"],
                "Item": {key: serializer.serialize(value) for key, value in finding.items()},
            }
            if deduplicate:
                kwargs.update(
                    {
                        "ConditionExpression": (
                            "attribute_not_exists(finding_id) OR #updated <> :updated"
                        ),
                        "ExpressionAttributeNames": {"#updated": "updated_at"},
                        "ExpressionAttributeValues": {
                            ":updated": serializer.serialize(finding["updated_at"])
                        },
                    }
                )
            try:
                dynamodb.put_item(**kwargs)
            except dynamodb.exceptions.ConditionalCheckFailedException:
                continue
            response = events.put_events(
                Entries=[
                    {
                        "Source": "cloudsec.telemetry",
                        "DetailType": "FindingIngested",
                        "EventBusName": env["SECURITY_BUS_NAME"],
                        "Detail": json.dumps(finding, default=str),
                    }
                ]
            )
            if response.get("FailedEntryCount", 0):
                raise RuntimeError("FindingIngested publication failed")
            stored += 1
        return {"processed": len(findings), "stored": stored}
    except Exception as exc:
        cloudwatch.put_metric_data(
            Namespace="CloudSec/Telemetry",
            MetricData=[{"MetricName": "ParseFailure", "Value": 1, "Unit": "Count"}],
        )
        sqs.send_message(
            QueueUrl=env["DLQ_URL"],
            MessageBody=json.dumps(
                {
                    "source": "telemetry-ingestion",
                    "error_type": type(exc).__name__,
                    "payload": event,
                },
                default=str,
            ),
        )
        raise
