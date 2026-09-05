import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lambda"))
from remediation.playbooks.detach_privilege_policy import detach_policy  # noqa: E402

ROLE = "arn:aws:iam::123456789012:role/app/TestRole"
POLICY = "arn:aws:iam::123456789012:policy/Admin"
EVIDENCE = {
    "role_arn": ROLE,
    "affected_resources": [POLICY],
    "attached_at": "2026-09-04T10:05:00Z",
    "incident_start": "2026-09-04T10:00:00Z",
    "incident_end": "2026-09-04T10:10:00Z",
}


class IAM:
    def __init__(self, attached=True):
        self.policies = [{"PolicyName": "Admin", "PolicyArn": POLICY}] if attached else []
        self.calls = []
        self.keep = False

    def get_role(self, **_kwargs):
        return {"Role": {"RoleName": "TestRole"}}

    def list_attached_role_policies(self, **_kwargs):
        return {"AttachedPolicies": self.policies}

    def detach_role_policy(self, **kwargs):
        self.calls.append(("detach", kwargs))
        if not self.keep:
            self.policies = []

    def attach_role_policy(self, **kwargs):
        self.calls.append(("attach", kwargs))


def run(iam, **overrides):
    args = {"approved": True, "evidence": EVIDENCE}
    args.update(overrides)
    return detach_policy(iam, ROLE, POLICY, **args)


def test_attached_policy_is_detached_and_pre_state_saved():
    result = run(IAM())
    assert result["changed"] and result["pre_remediation_state"]["attached_policies"]


def test_unattached_policy_is_idempotent():
    iam = IAM(False)
    assert not run(iam)["changed"] and not iam.calls


def test_pre_existing_policy_is_rejected():
    with pytest.raises(PermissionError, match="outside"):
        run(IAM(), evidence={**EVIDENCE, "attached_at": "2026-09-03T10:00:00Z"})


def test_iam_error_propagates():
    class Broken(IAM):
        def get_role(self, **_kwargs):
            raise RuntimeError("IAM error")

    with pytest.raises(RuntimeError, match="IAM error"):
        run(Broken())


def test_verification_failure_rolls_back():
    iam = IAM()
    iam.keep = True
    with pytest.raises(RuntimeError, match="verification"):
        run(iam)
    assert iam.calls[-1][0] == "attach"


def test_mismatched_evidence_is_rejected():
    with pytest.raises(PermissionError):
        run(IAM(), evidence={**EVIDENCE, "affected_resources": []})
