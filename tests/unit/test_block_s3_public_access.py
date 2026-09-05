import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lambda"))
from remediation.playbooks.block_s3_public_access import BLOCKED, block_public_access  # noqa: E402


class S3:
    def __init__(self, config=None, tags=None):
        self.config = config
        self.tags = tags or {}
        self.calls = []
        self.keep_old = False

    def head_bucket(self, **kwargs):
        self.calls.append(("head", kwargs))

    def get_bucket_tagging(self, **_kwargs):
        return {"TagSet": [{"Key": k, "Value": v} for k, v in self.tags.items()]}

    def get_public_access_block(self, **_kwargs):
        if self.config is None:
            exc = RuntimeError("missing")
            exc.response = {"Error": {"Code": "NoSuchPublicAccessBlockConfiguration"}}
            raise exc
        return {"PublicAccessBlockConfiguration": self.config}

    def put_public_access_block(self, **kwargs):
        self.calls.append(("put", kwargs))
        if not self.keep_old:
            self.config = kwargs["PublicAccessBlockConfiguration"]

    def delete_public_access_block(self, **kwargs):
        self.calls.append(("delete", kwargs))
        self.config = None


EVIDENCE = {"bucket_name": "evidence-bucket", "publicly_exposed": True}


def run(s3, **overrides):
    args = {"approved": True, "evidence": EVIDENCE}
    args.update(overrides)
    return block_public_access(s3, "evidence-bucket", **args)


def test_bucket_exists_is_blocked_and_pre_state_saved():
    old = {**BLOCKED, "RestrictPublicBuckets": False}
    result = run(S3(old))
    assert result["changed"] and result["pre_remediation_state"] == old


def test_bucket_not_found_propagates():
    class Missing(S3):
        def head_bucket(self, **_kwargs):
            raise RuntimeError("not found")

    with pytest.raises(RuntimeError, match="not found"):
        run(Missing())


def test_intentional_public_tag_escalates():
    with pytest.raises(PermissionError, match="escalation"):
        run(S3(tags={"intentional_public": "true"}))


def test_s3_error_propagates():
    class Broken(S3):
        def get_bucket_tagging(self, **_kwargs):
            raise RuntimeError("S3 error")

    with pytest.raises(RuntimeError, match="S3 error"):
        run(Broken())


def test_failed_verification_rolls_back_previous_configuration():
    old = {**BLOCKED, "BlockPublicAcls": False}
    s3 = S3(old)
    s3.keep_old = True
    with pytest.raises(RuntimeError, match="post-verification"):
        run(s3)
    assert s3.calls[-1][1]["PublicAccessBlockConfiguration"] == old


def test_already_blocked_is_idempotent():
    s3 = S3(dict(BLOCKED))
    assert run(s3)["changed"] is False
    assert all(call[0] != "put" for call in s3.calls)
