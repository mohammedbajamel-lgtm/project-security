import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lambda"))
from remediation.playbooks.disable_iam_key import disable_key  # noqa: E402


class Paginator:
    def __init__(self, iam):
        self.iam = iam

    def paginate(self, **_kwargs):
        return [{"AccessKeyMetadata": self.iam.keys}]


class IAM:
    def __init__(self, status="Active"):
        self.keys = [{"AccessKeyId": "AKIATEST", "Status": status}]
        self.calls = []
        self.fail_verify = False

    def get_paginator(self, _name):
        return Paginator(self)

    def update_access_key(self, **kwargs):
        self.calls.append(kwargs)
        if self.fail_verify and kwargs["Status"] == "Inactive":
            return
        self.keys[0]["Status"] = kwargs["Status"]


EVIDENCE = {
    "user_name": "alice",
    "access_key_id": "AKIATEST",
    "cloudtrail_used": True,
    "last_used": "now",
}


def test_disables_active_key_and_records_audit():
    iam = IAM()
    result = disable_key(iam, "alice", "AKIATEST", approved=True, evidence=EVIDENCE)
    assert result["changed"] and result["audit"]["new_status"] == "Inactive"


def test_inactive_is_idempotent():
    iam = IAM("Inactive")
    assert not disable_key(iam, "alice", "AKIATEST", approved=True, evidence=EVIDENCE)["changed"]
    assert iam.calls == []


@pytest.mark.parametrize(
    "approved,evidence",
    [
        (False, EVIDENCE),
        (True, {**EVIDENCE, "cloudtrail_used": False}),
        (True, {**EVIDENCE, "user_name": "other"}),
    ],
)
def test_requires_approval_and_matching_evidence(approved, evidence):
    with pytest.raises(PermissionError):
        disable_key(IAM(), "alice", "AKIATEST", approved=approved, evidence=evidence)


def test_missing_key_fails():
    iam = IAM()
    iam.keys = []
    with pytest.raises(ValueError):
        disable_key(iam, "alice", "AKIATEST", approved=True, evidence=EVIDENCE)


def test_post_check_failure_rolls_back():
    iam = IAM()
    iam.fail_verify = True
    with pytest.raises(RuntimeError):
        disable_key(iam, "alice", "AKIATEST", approved=True, evidence=EVIDENCE)
    assert iam.calls[-1]["Status"] == "Active"
