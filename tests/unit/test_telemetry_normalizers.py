"""Phase 3 normalization tests."""

from __future__ import annotations

import gzip
import io
import json
import sys
import types
from pathlib import Path

import pytest

INGESTION = Path(__file__).resolve().parents[2] / "lambda" / "ingestion"
sys.path.insert(0, str(INGESTION))

import cloudtrail_parser  # noqa: E402
import cloudtrail_s3_runtime  # noqa: E402
import config_ingestor  # noqa: E402
import guardduty_ingestor  # noqa: E402
import normalizer  # noqa: E402
import securityhub_ingestor  # noqa: E402
import telemetry_runtime  # noqa: E402


def test_guardduty_normalization_and_invalid_event():
    event = {
        "id": "e1",
        "account": "123456789012",
        "region": "us-east-1",
        "time": "2026-09-04T00:00:00Z",
        "detail": {"id": "f1", "severity": 8, "updatedAt": "2026-09-04T00:00:00Z", "service": {}},
    }
    assert guardduty_ingestor.normalize(event)["severity"] == "P1"
    with pytest.raises(normalizer.InvalidTelemetryError):
        guardduty_ingestor.normalize({})


@pytest.mark.parametrize("label,priority", [("MEDIUM", "P3"), ("HIGH", "P2"), ("CRITICAL", "P1")])
def test_securityhub_accepted_severities(label: str, priority: str):
    event = {
        "detail": {
            "findings": [
                {
                    "Id": "f1",
                    "AwsAccountId": "123456789012",
                    "Region": "us-east-1",
                    "UpdatedAt": "2026-09-04T00:00:00Z",
                    "Severity": {"Label": label},
                }
            ]
        }
    }
    finding = securityhub_ingestor.normalize(event)[0]
    assert finding["severity"] == priority
    assert finding["ingested_at"] == finding["updated_at"]


@pytest.mark.parametrize("label", ["LOW", "INFORMATIONAL"])
def test_securityhub_filters_low_severities(label: str):
    assert (
        securityhub_ingestor.normalize({"detail": {"findings": [{"Severity": {"Label": label}}]}})
        == []
    )


def test_cloudtrail_is_deterministic():
    record = {
        "eventID": "e1",
        "eventTime": "2026-09-04T00:00:00Z",
        "recipientAccountId": "123456789012",
        "awsRegion": "us-east-1",
    }
    assert cloudtrail_parser.normalize_record(record) == cloudtrail_parser.normalize_record(record)


def test_config_normalization_and_invalid_event():
    event = {
        "detail": {
            "configurationItem": {
                "resourceType": "AWS::S3::Bucket",
                "resourceId": "bucket",
                "awsAccountId": "123456789012",
                "awsRegion": "us-east-1",
                "configurationItemCaptureTime": "2026-09-04T00:00:00Z",
                "configuration": {},
            }
        }
    }
    assert config_ingestor.normalize(event)["source_type"] == "aws_config"
    with pytest.raises(normalizer.InvalidTelemetryError):
        config_ingestor.normalize({"detail": {"configurationItem": {}}})


def test_compact_hashes_oversized_values():
    assert normalizer.compact({"value": "x" * 100}, limit=10)["truncated"] is True


def test_cloudtrail_s3_runtime_validates_and_processes(monkeypatch):
    record = {
        "eventID": "e1",
        "eventTime": "2026-09-04T00:00:00Z",
        "recipientAccountId": "123456789012",
        "awsRegion": "us-east-1",
    }
    body = gzip.compress(json.dumps({"Records": [record]}).encode())

    class S3:
        def get_object(self, **kwargs):
            return {"Body": io.BytesIO(body)}

    runtime = types.SimpleNamespace(deliver=lambda *args, **kwargs: {"processed": 1, "stored": 1})
    monkeypatch.setitem(sys.modules, "telemetry_runtime", runtime)
    monkeypatch.setattr(cloudtrail_s3_runtime.boto3, "client", lambda service: S3())
    monkeypatch.setenv("CLOUDTRAIL_BUCKET", "audit-bucket")
    event = {
        "Records": [
            {
                "s3": {
                    "bucket": {"name": "audit-bucket"},
                    "object": {"key": "CloudTrail%2Flog.json.gz"},
                }
            }
        ]
    }
    assert cloudtrail_s3_runtime.process_notifications(event) == {"processed": 1, "stored": 1}


def test_cloudtrail_s3_runtime_rejects_unexpected_object(monkeypatch):
    monkeypatch.setenv("CLOUDTRAIL_BUCKET", "audit-bucket")
    monkeypatch.setattr(cloudtrail_s3_runtime.boto3, "client", lambda service: object())
    event = {
        "Records": [
            {"s3": {"bucket": {"name": "wrong"}, "object": {"key": "CloudTrail%2Flog.json.gz"}}}
        ]
    }
    with pytest.raises(normalizer.InvalidTelemetryError):
        cloudtrail_s3_runtime.process_notifications(event)


class ConditionalFailureError(Exception):
    pass


class FakeClient:
    def __init__(self, service: str, *, conditional: bool = False):
        self.service = service
        self.conditional = conditional
        self.calls = []
        self.exceptions = types.SimpleNamespace(
            ConditionalCheckFailedException=ConditionalFailureError
        )

    def put_item(self, **kwargs):
        self.calls.append(kwargs)
        if self.conditional:
            raise ConditionalFailureError

    def put_events(self, **kwargs):
        self.calls.append(kwargs)
        return {"FailedEntryCount": 0}

    def put_metric_data(self, **kwargs):
        self.calls.append(kwargs)

    def send_message(self, **kwargs):
        self.calls.append(kwargs)


class FakeBoto:
    def __init__(self, *, conditional: bool = False):
        self.clients = {
            name: FakeClient(name, conditional=conditional and name == "dynamodb")
            for name in ("dynamodb", "events", "sqs", "cloudwatch")
        }

    def client(self, name: str):
        return self.clients[name]


RUNTIME_ENV = {"FINDINGS_TABLE": "findings", "SECURITY_BUS_NAME": "bus", "DLQ_URL": "dlq"}


def test_delivery_writes_and_publishes():
    sdk = FakeBoto()
    result = telemetry_runtime.deliver(
        {"raw": True},
        lambda event: {"finding_id": "f1", "updated_at": "now"},
        boto3_module=sdk,
        env=RUNTIME_ENV,
    )
    assert result == {"processed": 1, "stored": 1}
    assert len(sdk.clients["dynamodb"].calls) == 1
    assert len(sdk.clients["events"].calls) == 1


def test_delivery_deduplicates_conditional_failure():
    sdk = FakeBoto(conditional=True)
    result = telemetry_runtime.deliver(
        {},
        lambda event: [{"finding_id": "f1", "updated_at": "now"}],
        boto3_module=sdk,
        env=RUNTIME_ENV,
        deduplicate=True,
    )
    assert result == {"processed": 1, "stored": 0}


def test_delivery_failure_emits_metric_and_routes_dlq():
    sdk = FakeBoto()
    with pytest.raises(normalizer.InvalidTelemetryError):
        telemetry_runtime.deliver(
            {"bad": True},
            lambda event: (_ for _ in ()).throw(normalizer.InvalidTelemetryError("bad")),
            boto3_module=sdk,
            env=RUNTIME_ENV,
        )
    assert sdk.clients["cloudwatch"].calls[0]["Namespace"] == "CloudSec/Telemetry"
    assert sdk.clients["sqs"].calls
