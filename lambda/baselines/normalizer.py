"""Normalize CloudTrail management events for baseline computation."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any


def normalize_event(event: dict[str, Any]) -> dict[str, Any] | None:
    try:
        detail = json.loads(event.get("CloudTrailEvent", "{}"))
        identity = detail["userIdentity"]
        principal = identity.get("arn") or identity.get("sessionContext", {}).get(
            "sessionIssuer", {}
        ).get("arn")
        if not principal:
            return None
        time = datetime.fromisoformat(event["EventTime"].isoformat())
        role = identity.get("sessionContext", {}).get("sessionIssuer", {}).get("arn")
        return {
            "principal_arn": principal,
            "region": detail.get("awsRegion"),
            "api_call": event.get("EventName") or detail.get("eventName"),
            "service": detail.get("eventSource", "").split(".")[0],
            "hour": time.hour,
            "event_time": time,
            "assumed_role": role,
            "source_account": detail.get("recipientAccountId", ""),
        }
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None
