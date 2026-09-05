"""Bounded S3/gzip processing for CloudTrail notifications."""

from __future__ import annotations

import gzip
import json
import os
from typing import Any
from urllib.parse import unquote_plus

import boto3
from normalizer import InvalidTelemetryError

MAX_RECORDS = 1000
MAX_COMPRESSED_BYTES = 10 * 1024 * 1024


def process_notifications(event: dict[str, Any]) -> dict[str, int]:
    notifications = event.get("Records")
    if not isinstance(notifications, list):
        raise InvalidTelemetryError("missing S3 Records")
    expected_bucket = os.environ.get("CLOUDTRAIL_BUCKET")
    if not expected_bucket:
        raise RuntimeError("CLOUDTRAIL_BUCKET is not configured")
    s3 = boto3.client("s3")
    from cloudtrail_parser import normalize_record
    from telemetry_runtime import deliver

    processed = stored = 0
    for notification in notifications:
        bucket = notification.get("s3", {}).get("bucket", {}).get("name")
        key = unquote_plus(notification.get("s3", {}).get("object", {}).get("key", ""))
        valid_key = key.startswith("CloudTrail/") and key.endswith(".json.gz")
        if bucket != expected_bucket or not valid_key:
            raise InvalidTelemetryError("unexpected CloudTrail object")
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read(MAX_COMPRESSED_BYTES + 1)
        if len(body) > MAX_COMPRESSED_BYTES:
            raise InvalidTelemetryError("CloudTrail object exceeds processing limit")
        records = json.loads(gzip.decompress(body)).get("Records")
        if not isinstance(records, list):
            raise InvalidTelemetryError("invalid CloudTrail Records")
        for record in records[: MAX_RECORDS - processed]:
            result = deliver(record, normalize_record, boto3_module=boto3, env=os.environ)
            processed += result["processed"]
            stored += result["stored"]
        if processed >= MAX_RECORDS:
            break
    return {"processed": processed, "stored": stored}
