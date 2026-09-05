"""Phase 5 behavior baseline acceptance tests."""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lambda"))

from baselines.anomaly_detector import detect_anomalies
from baselines.compute_baseline import compute, confidence, lookup_all


def trail_event(day=0, **overrides):
    stamp = datetime(2026, 8, 1, 4, tzinfo=UTC) + timedelta(days=day)
    detail = {
        "userIdentity": {"arn": "arn:aws:iam::111:user/alice"},
        "awsRegion": "us-east-1",
        "eventSource": "s3.amazonaws.com",
        "eventName": "GetObject",
        "recipientAccountId": "111",
    }
    detail.update(overrides)
    return {
        "EventTime": stamp,
        "EventName": detail["eventName"],
        "CloudTrailEvent": json.dumps(detail),
    }


def test_compute_full_short_and_new_baselines():
    principal = "arn:aws:iam::111:user/alice"
    full = compute(principal, [trail_event(0), trail_event(29)])
    assert full["confidence_score"] == 1.0 and full["activity_count_30d"] == 2
    assert isinstance(full["confidence_score"], Decimal)
    assert full["common_api_calls"] == {"GetObject": 2}
    assert compute(principal, [trail_event(0), trail_event(5)])["confidence_score"] == Decimal(
        "0.2"
    )
    assert compute("missing", [trail_event()])["new_principal"] is True
    assert confidence(7) == 0.5


def test_malformed_event_is_ignored():
    baseline = compute("p", [{"CloudTrailEvent": "not-json"}])
    assert baseline["confidence_score"] == 0.0


def test_cloudtrail_pagination():
    class Client:
        calls = 0

        def lookup_events(self, **kwargs):
            self.calls += 1
            return {"Events": [trail_event()], **({"NextToken": "n"} if self.calls == 1 else {})}

    client = Client()
    assert (
        len(lookup_all(client, datetime.now(UTC), datetime.now(UTC), sleeper=lambda _: None)) == 2
    )


def test_cloudtrail_throttling_retries():
    from botocore.exceptions import ClientError

    class Client:
        calls = 0

        def lookup_events(self, **kwargs):
            self.calls += 1
            if self.calls == 1:
                raise ClientError({"Error": {"Code": "ThrottlingException"}}, "LookupEvents")
            return {"Events": []}

    client = Client()
    lookup_all(client, datetime.now(UTC), datetime.now(UTC), sleeper=lambda _: None)
    assert client.calls == 2


def test_cloudtrail_pagination_is_bounded():
    class Client:
        calls = 0

        def lookup_events(self, **kwargs):
            self.calls += 1
            return {"Events": [], "NextToken": "more"}

    client = Client()
    lookup_all(client, datetime.now(UTC), datetime.now(UTC), sleeper=lambda _: None, max_pages=3)
    assert client.calls == 3


def test_anomaly_scores():
    baseline = {
        "confidence_score": 1.0,
        "normal_regions": ["us-east-1"],
        "common_api_calls": {"GetObject": 9},
        "typical_hours": [4],
        "common_assumed_roles": ["known"],
    }
    normal = {
        "source_region": "us-east-1",
        "api_call": "GetObject",
        "finding_time": "2026-09-04T04:00:00Z",
        "assumed_role": "known",
    }
    assert detect_anomalies(normal, baseline)["anomaly_score"] == 0
    unusual = {
        "source_region": "eu-west-1",
        "api_call": "DeleteBucket",
        "finding_time": "2026-09-04T14:00:00Z",
        "assumed_role": "unknown",
    }
    assert detect_anomalies(unusual, baseline)["anomaly_score"] == 1.0
    assert detect_anomalies({}, None)["anomaly_score"] == 0.5
    assert detect_anomalies({}, {"confidence_score": 0.2})["anomaly_score"] is None
