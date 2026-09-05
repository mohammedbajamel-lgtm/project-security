import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lambda"))
from verification.finding_rechecker import recheck_findings  # noqa: E402
from verification.resolution_engine import resolve_or_escalate  # noqa: E402
from verification.state_checker import (  # noqa: E402
    verify_cloudtrail_logging,
    verify_ec2_isolated,
    verify_iam_key_disabled,
    verify_policy_detached,
    verify_s3_public_blocked,
    verify_sg_ingress_revoked,
)

NOW = datetime(2026, 9, 4, 12, tzinfo=UTC)


class IAM:
    def list_access_keys(self, **_kwargs):
        return {"AccessKeyMetadata": [{"AccessKeyId": "K", "Status": "Inactive"}]}

    def list_attached_role_policies(self, **_kwargs):
        return {"AttachedPolicies": []}


class EC2:
    def describe_security_group_rules(self, **_kwargs):
        return {"SecurityGroupRules": []}

    def describe_instances(self, **_kwargs):
        return {"Reservations": [{"Instances": [{"SecurityGroups": [{"GroupId": "iso"}]}]}]}

    def describe_snapshots(self, **_kwargs):
        return {"Snapshots": [{"State": "completed"}]}


class S3:
    def get_public_access_block(self, **_kwargs):
        return {
            "PublicAccessBlockConfiguration": {
                key: True
                for key in (
                    "BlockPublicAcls",
                    "IgnorePublicAcls",
                    "BlockPublicPolicy",
                    "RestrictPublicBuckets",
                )
            }
        }


class Trail:
    def get_trail_status(self, **_kwargs):
        return {"IsLogging": True, "LatestDeliveryTime": NOW - timedelta(minutes=1)}


def test_all_six_state_verifiers_pass_secure_state():
    assert verify_iam_key_disabled(IAM(), "u", "K", now=NOW)["verified"]
    assert verify_sg_ingress_revoked(EC2(), "sg", "0.0.0.0/0", 22, now=NOW)["verified"]
    assert verify_s3_public_blocked(S3(), "b", now=NOW)["verified"]
    assert verify_ec2_isolated(EC2(), "i", "iso", ["snap"], now=NOW)["verified"]
    assert verify_cloudtrail_logging(Trail(), "t", now=NOW)["verified"]
    assert verify_policy_detached(IAM(), "r", "p", now=NOW)["verified"]


def test_verifiers_fail_closed_on_aws_errors():
    class Broken:
        def __getattr__(self, _name):
            raise RuntimeError("AWS error")

    checks = [
        verify_iam_key_disabled(Broken(), "u", "k"),
        verify_sg_ingress_revoked(Broken(), "sg", "c", 22),
        verify_s3_public_blocked(Broken(), "b"),
        verify_ec2_isolated(Broken(), "i", "sg", []),
        verify_cloudtrail_logging(Broken(), "t"),
        verify_policy_detached(Broken(), "r", "p"),
    ]
    assert not any(check["verified"] for check in checks)


class Findings:
    def get_findings(self, **_kwargs):
        return {"Findings": [{"Service": {"Archived": True}}]}

    def batch_get_findings(self, **_kwargs):
        return {"Findings": [{"Compliance": {"Status": "PASSED"}}]}

    def lookup_events(self, **_kwargs):
        return {"Events": []}


def test_all_finding_sources_must_be_contained():
    findings = [
        {"source": "guardduty", "finding_id": "g", "detector_id": "d"},
        {"source": "securityhub", "finding_id": "s", "identifier": {}},
        {"source": "cloudtrail", "finding_id": "c", "event_name": "StopLogging"},
    ]
    assert recheck_findings(
        findings, guardduty=Findings(), securityhub=Findings(), cloudtrail=Findings(), now=NOW
    )["contained"]


def test_preverified_lab_finding_is_contained_without_source_api_call():
    result = recheck_findings(
        [{"source": "lab_simulation", "finding_id": "e2e", "state_verified": True}],
        guardduty=Findings(),
        securityhub=Findings(),
        cloudtrail=Findings(),
        allow_preverified=True,
        now=NOW,
    )
    assert result["contained"] is True


class Recorder:
    def __init__(self):
        self.calls = []

    def update_item(self, **kwargs):
        self.calls.append(kwargs)

    def put_events(self, **kwargs):
        self.calls.append(kwargs)

    def publish(self, **kwargs):
        self.calls.append(kwargs)


def test_resolution_requires_every_condition_and_failure_escalates():
    incident = {
        "incident_id": "i",
        "event_time": "2026-09-04T11:00:00+00:00",
        "created_at": "2026-09-04T11:00:00+00:00",
        "severity": "HIGH",
    }
    table, events, sns = Recorder(), Recorder(), Recorder()
    passed = {
        "state_checks": [{"verified": True}],
        "containment": {"contained": True},
        "no_new_findings": True,
    }
    assert (
        resolve_or_escalate(table, events, sns, incident, passed, topic_arn="topic", now=NOW)[
            "status"
        ]
        == "RESOLVED"
    )
    failed = {**passed, "no_new_findings": False}
    assert (
        resolve_or_escalate(table, events, sns, incident, failed, topic_arn="topic", now=NOW)[
            "status"
        ]
        == "ESCALATED"
    )
    assert sns.calls
