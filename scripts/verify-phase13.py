"""Controlled live checkpoint for Phase 13; creates only TTL-limited test incidents."""

from __future__ import annotations

import json
import os
import time
import uuid
from datetime import UTC, datetime
from decimal import Decimal

import boto3

REGION = "us-east-1"
TABLE = "cloudsec-dev-incidents"
FUNCTION = "cloudsec-dev-verification-engine"
SAFE_BUCKET = os.environ.get("CLOUDSEC_PHASE13_SAFE_BUCKET", "")


def run_case(expected: str, bucket: str) -> str:
    clock = datetime.now(UTC)
    incident_id = f"phase13-{expected.lower()}-{uuid.uuid4().hex[:12]}"
    event_time = clock.isoformat()
    table = boto3.resource("dynamodb", region_name=REGION).Table(TABLE)
    item = {
        "incident_id": incident_id,
        "event_time": event_time,
        "created_at": event_time,
        "status": "VERIFYING",
        "version": Decimal(1),
        "severity": "LOW",
        "finding_id": f"synthetic-{incident_id}",
        "ttl": int(time.time()) + 86400,
        "synthetic_checkpoint": True,
    }
    table.put_item(Item=item)
    event = {
        "detail": {
            "action": "block_s3_public_access",
            "params": {"bucket_name": bucket},
            "result": {},
            "incident": item,
            "findings": [
                {
                    "source": "cloudtrail",
                    "finding_id": item["finding_id"],
                    "event_name": f"CloudSecNeverOccurred{uuid.uuid4().hex}",
                }
            ],
            "new_findings": [],
        }
    }
    response = boto3.client("lambda", region_name=REGION).invoke(
        FunctionName=FUNCTION,
        InvocationType="RequestResponse",
        Payload=json.dumps(event, default=str).encode(),
    )
    payload = json.loads(response["Payload"].read())
    if response.get("FunctionError"):
        raise RuntimeError(payload)
    current = table.get_item(
        Key={"incident_id": incident_id, "event_time": event_time},
        ConsistentRead=True,
    )["Item"]
    if current["status"] != expected:
        raise AssertionError(f"expected {expected}, got {current['status']}: {payload}")
    print(f"PASS: {incident_id} transitioned to {expected}")
    return incident_id


def main():
    if not SAFE_BUCKET.startswith("cloudsec-dev-"):
        raise RuntimeError("Set CLOUDSEC_PHASE13_SAFE_BUCKET to the deployed safety-policy bucket")
    run_case("RESOLVED", SAFE_BUCKET)
    run_case("ESCALATED", "cloudsec-dev-phase13-intentionally-missing")
    print("Phase 13 controlled resolve/escalate checkpoint passed.")


if __name__ == "__main__":
    main()
