import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lambda"))
from remediation.playbooks.revoke_sg_ingress import revoke_ingress  # noqa: E402

RULE = {
    "SecurityGroupRuleId": "sgr-123",
    "GroupId": "sg-123",
    "IsEgress": False,
    "IpProtocol": "tcp",
    "FromPort": 22,
    "ToPort": 22,
    "CidrIpv4": "0.0.0.0/0",
}
EVIDENCE = {
    "group_id": "sg-123",
    "rule_id": "sgr-123",
    "cidr": "0.0.0.0/0",
    "from_port": 22,
    "to_port": 22,
    "protocol": "tcp",
    "rule_changed_at": "2026-09-04T10:05:00Z",
    "incident_start": "2026-09-04T10:00:00Z",
    "incident_end": "2026-09-04T10:10:00Z",
}


class EC2:
    def __init__(self, rules=None):
        self.rules = [dict(RULE)] if rules is None else rules
        self.calls = []
        self.keep_after_revoke = False

    def describe_security_groups(self, **kwargs):
        self.calls.append(("describe_groups", kwargs))
        return {"SecurityGroups": [{"GroupId": "sg-123"}]}

    def describe_security_group_rules(self, **_kwargs):
        return {"SecurityGroupRules": self.rules}

    def revoke_security_group_ingress(self, **kwargs):
        self.calls.append(("revoke", kwargs))
        if not self.keep_after_revoke:
            self.rules = []

    def authorize_security_group_ingress(self, **kwargs):
        self.calls.append(("authorize", kwargs))


def run(ec2, **overrides):
    args = dict(
        group_id="sg-123",
        cidr="0.0.0.0/0",
        from_port=22,
        to_port=22,
        protocol="tcp",
        rule_id="sgr-123",
        approved=True,
        evidence=EVIDENCE,
    )
    args.update(overrides)
    return revoke_ingress(ec2, **args)


def test_rule_exists_is_revoked_and_pre_state_saved():
    result = run(EC2())
    assert result["changed"] is True
    assert result["pre_remediation_state"] == RULE


def test_rule_not_found_is_idempotent_but_group_is_checked():
    ec2 = EC2([])
    assert run(ec2)["changed"] is False
    assert ec2.calls[0][0] == "describe_groups"


def test_pre_existing_rule_is_rejected():
    evidence = {**EVIDENCE, "rule_changed_at": "2026-09-03T10:05:00Z"}
    with pytest.raises(PermissionError, match="incident window"):
        run(EC2(), evidence=evidence)


def test_ec2_error_propagates():
    class Broken(EC2):
        def describe_security_groups(self, **_kwargs):
            raise RuntimeError("EC2 error")

    with pytest.raises(RuntimeError, match="EC2 error"):
        run(Broken())


def test_failed_verification_rolls_back_exact_rule():
    ec2 = EC2()
    ec2.keep_after_revoke = True
    with pytest.raises(RuntimeError, match="post-verification"):
        run(ec2)
    assert ec2.calls[-1][0] == "authorize"
    assert ec2.calls[-1][1]["IpPermissions"][0]["IpRanges"] == [{"CidrIp": "0.0.0.0/0"}]


def test_non_public_or_non_matching_evidence_is_rejected():
    with pytest.raises(PermissionError):
        run(EC2(), cidr="10.0.0.0/8")
