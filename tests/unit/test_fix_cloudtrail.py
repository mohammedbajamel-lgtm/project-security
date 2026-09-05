import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lambda"))
from remediation.playbooks.fix_cloudtrail import fix_cloudtrail  # noqa: E402


class CloudTrail:
    def __init__(self, exists=True, logging=False, validation=False):
        self.name = "audit" if exists else None
        self.logging = logging
        self.validation = validation
        self.calls = []

    def describe_trails(self, **kwargs):
        if self.name not in kwargs["trailNameList"]:
            return {"trailList": []}
        return {
            "trailList": [
                {
                    "Name": self.name,
                    "S3BucketName": "logs",
                    "LogFileValidationEnabled": self.validation,
                }
            ]
        }

    def get_trail_status(self, **_kwargs):
        return {"IsLogging": self.logging}

    def update_trail(self, **kwargs):
        self.calls.append(("update", kwargs))
        self.validation = True

    def start_logging(self, **kwargs):
        self.calls.append(("start", kwargs))
        self.logging = True

    def create_trail(self, **kwargs):
        self.calls.append(("create", kwargs))
        self.name = kwargs["Name"]
        self.validation = True
        return {
            "Name": self.name,
            "S3BucketName": kwargs["S3BucketName"],
            "LogFileValidationEnabled": True,
        }


NOW = datetime(2026, 9, 4, 12, tzinfo=UTC)
EVIDENCE = {"trail_name": "audit", "s3_bucket": "logs"}


def test_disabled_trail_is_started_and_validation_enabled():
    result = fix_cloudtrail(CloudTrail(), "audit", approved=True, evidence=EVIDENCE, now=NOW)
    assert result["changed"] and result["status"] == "LOGGING"


def test_enabled_trail_is_idempotent():
    client = CloudTrail(logging=True, validation=True)
    assert not fix_cloudtrail(client, "audit", approved=True, evidence=EVIDENCE, now=NOW)["changed"]


def test_recently_deleted_trail_is_recreated():
    evidence = {
        **EVIDENCE,
        "deleted_at": "2026-09-04T11:00:00Z",
        "previous_configuration": {"S3BucketName": "logs", "IsMultiRegionTrail": True},
    }
    result = fix_cloudtrail(CloudTrail(False), "audit", approved=True, evidence=evidence, now=NOW)
    assert "-recreated-" in result["trail_name"]


def test_cloudtrail_error_propagates():
    class Broken(CloudTrail):
        def describe_trails(self, *args, **kwargs):
            raise RuntimeError("CloudTrail error")

    with pytest.raises(RuntimeError, match="CloudTrail error"):
        fix_cloudtrail(Broken(), "audit", approved=True, evidence=EVIDENCE, now=NOW)


def test_post_verification_failure_is_detected():
    class BrokenStart(CloudTrail):
        def start_logging(self, **_kwargs):
            pass

    with pytest.raises(RuntimeError, match="post-verification"):
        fix_cloudtrail(BrokenStart(), "audit", approved=True, evidence=EVIDENCE, now=NOW)
