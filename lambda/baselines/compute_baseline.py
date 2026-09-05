"""Daily behavior-baseline computation from CloudTrail LookupEvents."""

from __future__ import annotations

import os
import time
from collections import Counter
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

import boto3
from botocore.exceptions import ClientError
from common.logger import log_invocation

from .normalizer import normalize_event


def confidence(days: int) -> Decimal:
    return Decimal("1.0") if days >= 30 else Decimal("0.5") if days >= 7 else Decimal("0.2")


def compute(principal_arn: str, events: list[dict[str, Any]], today=None) -> dict[str, Any]:
    normalized = [
        item
        for event in events
        if (item := normalize_event(event)) and item["principal_arn"] == principal_arn
    ]
    day = today or datetime.now(UTC).date()
    if not normalized:
        return {
            "principal_arn": principal_arn,
            "baseline_date": day.isoformat(),
            "confidence_score": Decimal("0.0"),
            "new_principal": True,
            "activity_count_30d": 0,
        }
    dates = [row["event_time"].date() for row in normalized]
    observed_days = (max(dates) - min(dates)).days + 1
    calls = Counter(row["api_call"] for row in normalized if row["api_call"])
    account = next((row["source_account"] for row in normalized if row["source_account"]), "")
    return {
        "principal_arn": principal_arn,
        "baseline_date": day.isoformat(),
        "source_account": account,
        "normal_regions": sorted({row["region"] for row in normalized if row["region"]}),
        "common_api_calls": dict(calls.most_common(20)),
        "common_services": sorted({row["service"] for row in normalized if row["service"]}),
        "typical_hours": sorted({row["hour"] for row in normalized}),
        "common_assumed_roles": sorted(
            {row["assumed_role"] for row in normalized if row["assumed_role"]}
        ),
        "activity_count_30d": len(normalized),
        "confidence_score": confidence(observed_days),
        "new_principal": False,
        "ttl": int(datetime.now(UTC).timestamp()) + 90 * 86400,
    }


def lookup_all(
    client: Any,
    start: datetime,
    end: datetime,
    *,
    sleeper=time.sleep,
    max_pages: int = 100,
) -> list[dict[str, Any]]:
    events, token = [], None
    for _page in range(max_pages):
        args = {"StartTime": start, "EndTime": end, "MaxResults": 50}
        if token:
            args["NextToken"] = token
        for attempt in range(8):
            try:
                response = client.lookup_events(**args)
                break
            except ClientError as exc:
                if (
                    exc.response.get("Error", {}).get("Code") != "ThrottlingException"
                    or attempt == 7
                ):
                    raise
                sleeper(min(2**attempt, 16))
        events.extend(response.get("Events", []))
        token = response.get("NextToken")
        if not token:
            return events
        # LookupEvents has a low account-level request rate. Pace pagination
        # even after successful responses to avoid consuming the burst quota.
        sleeper(1.1)
    return events


@log_invocation("baseline-computation")
def lambda_handler(event, context):
    now = datetime.now(UTC)
    trail_events = lookup_all(boto3.client("cloudtrail"), now - timedelta(days=30), now)
    principals = sorted(
        {row["principal_arn"] for raw in trail_events if (row := normalize_event(raw))}
    )
    table = boto3.resource("dynamodb").Table(os.environ["BASELINES_TABLE_NAME"])
    for principal in principals:
        table.put_item(
            Item=compute(principal, trail_events),
            ConditionExpression="attribute_not_exists(principal_arn) OR baseline_date = :date",
            ExpressionAttributeValues={":date": now.date().isoformat()},
        )
    return {"principals_processed": len(principals)}
