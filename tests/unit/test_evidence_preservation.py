import hashlib
import io
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lambda"))
from evidence.analysis_storage import store_analysis  # noqa: E402
from evidence.config_snapshot import capture_config_snapshot  # noqa: E402
from evidence.manifest_generator import generate_manifest  # noqa: E402
from evidence.remediation_history import store_remediation_history  # noqa: E402


class S3:
    def __init__(self):
        self.objects = {}

    def put_object(self, **kwargs):
        assert kwargs["ServerSideEncryption"] == "aws:kms"
        self.objects[kwargs["Key"]] = kwargs["Body"]

    def list_objects_v2(self, **kwargs):
        return {
            "Contents": [{"Key": key} for key in self.objects if key.startswith(kwargs["Prefix"])]
        }

    def get_object(self, **kwargs):
        return {"Body": io.BytesIO(self.objects[kwargs["Key"]])}

    def get_bucket_policy(self, **_kwargs):
        return {"Policy": "{}"}

    def get_public_access_block(self, **_kwargs):
        return {"PublicAccessBlockConfiguration": {"BlockPublicAcls": True}}


def test_manifest_hashes_each_file_and_overall_hash():
    s3 = S3()
    s3.objects["evidence/i/a.json"] = b"a"
    s3.objects["evidence/i/b.json"] = b"b"
    manifest = generate_manifest(s3, "bucket", "i", "key", now=datetime(2026, 1, 1, tzinfo=UTC))
    hashes = [hashlib.sha256(value).hexdigest() for value in (b"a", b"b")]
    assert manifest["total_files"] == 2
    assert manifest["overall_sha256"] == hashlib.sha256("".join(hashes).encode()).hexdigest()


def test_analysis_storage_accepts_only_validated_minimized_reports():
    s3 = S3()
    keys = store_analysis(
        s3,
        "b",
        "i",
        "kms",
        {"validation_status": "VALID", "citation_validation_results": []},
        {"risk": 2},
        {"verified": True},
    )
    assert len(keys) == 3
    with pytest.raises(ValueError, match="raw model"):
        store_analysis(
            s3, "b", "i", "kms", {"validation_status": "VALID", "raw_prompt": "secret"}, {}, {}
        )


class Client:
    def get_user(self, **_kwargs):
        return {"User": {"UserName": "u"}}

    def list_attached_user_policies(self, **_kwargs):
        return {"AttachedPolicies": []}

    def get_role(self, **_kwargs):
        return {"Role": {"RoleName": "r"}}

    def describe_instances(self, **_kwargs):
        return {"Reservations": []}

    def describe_security_group_rules(self, **_kwargs):
        return {"SecurityGroupRules": []}

    def get_trail_status(self, **_kwargs):
        return {"IsLogging": True}


def test_combined_configuration_snapshot_supports_all_resource_types():
    s3, client = S3(), Client()
    resources = [
        {"type": "iam_user", "name": "u"},
        {"type": "iam_role", "name": "r"},
        {"type": "s3_bucket", "name": "b"},
        {"type": "ec2_instance", "id": "i"},
        {"type": "security_group", "id": "sg"},
        {"type": "cloudtrail", "name": "t"},
    ]
    result = capture_config_snapshot(
        {"iam": client, "s3": s3, "ec2": client, "cloudtrail": client},
        "b",
        "i",
        resources,
        "kms",
        "actor",
    )
    assert len(result["resources"]) == 6


class Audit:
    def scan(self, **_kwargs):
        return {"Items": [{"execution_id": "e"}]}


class SFN:
    def get_execution_history(self, **_kwargs):
        return {"events": [{"id": 1}]}


def test_remediation_history_aggregates_audit_and_execution_events():
    s3 = S3()
    result = store_remediation_history(s3, Audit(), SFN(), "b", "i", ["arn:e"], "kms")
    stored = json.loads(s3.objects[result["s3_key"]])
    assert stored["audit_events"] and stored["executions"][0]["events"]
