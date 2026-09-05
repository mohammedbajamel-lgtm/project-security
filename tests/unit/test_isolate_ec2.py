import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lambda"))
from remediation.playbooks.isolate_ec2 import isolate_instance  # noqa: E402

INSTANCE = {
    "InstanceId": "i-123",
    "VpcId": "vpc-123",
    "State": {"Name": "running"},
    "SecurityGroups": [{"GroupId": "sg-original"}],
    "BlockDeviceMappings": [{"Ebs": {"VolumeId": "vol-123"}}],
    "Tags": [],
}


class EC2:
    def __init__(self, instance=None):
        self.instance = dict(INSTANCE if instance is None else instance)
        self.calls = []
        self.fail_snapshot = False

    def describe_instances(self, **_kwargs):
        return {"Reservations": [{"Instances": [self.instance]}]}

    def describe_security_groups(self, **kwargs):
        if "Filters" in kwargs:
            return {"SecurityGroups": [{"GroupId": "sg-isolate"}]}
        return {"SecurityGroups": [{"GroupId": "sg-isolate", "IpPermissionsEgress": []}]}

    def modify_instance_attribute(self, **kwargs):
        self.calls.append(("modify", kwargs))
        self.instance["SecurityGroups"] = [{"GroupId": group} for group in kwargs["Groups"]]

    def create_snapshot(self, **kwargs):
        self.calls.append(("snapshot", kwargs))
        if self.fail_snapshot:
            raise RuntimeError("snapshot error")
        return {"SnapshotId": "snap-123"}

    def create_tags(self, **kwargs):
        self.calls.append(("tags", kwargs))

    def describe_snapshots(self, **_kwargs):
        return {"Snapshots": [{"State": "pending"}]}


def run(ec2, **overrides):
    args = {"env": "dev", "approved": True, "evidence": {"instance_id": "i-123"}}
    args.update(overrides)
    return isolate_instance(ec2, "i-123", "INC-1", **args)


def test_running_instance_is_isolated_and_snapshotted():
    result = run(EC2())
    assert result["status"] == "VERIFYING" and result["snapshot_ids"] == ["snap-123"]
    assert result["pre_remediation_state"]["security_group_ids"] == ["sg-original"]


def test_stopped_instance_is_rejected():
    with pytest.raises(ValueError, match="running"):
        run(EC2({**INSTANCE, "State": {"Name": "stopped"}}))


def test_no_isolate_tag_is_rejected():
    instance = {**INSTANCE, "Tags": [{"Key": "cloudsec_no_isolate", "Value": "true"}]}
    with pytest.raises(PermissionError, match="excluded"):
        run(EC2(instance))


def test_ec2_error_propagates():
    class Broken(EC2):
        def describe_instances(self, **_kwargs):
            raise RuntimeError("EC2 error")

    with pytest.raises(RuntimeError, match="EC2 error"):
        run(Broken())


def test_verification_failure_rolls_back_original_group():
    class BadVerify(EC2):
        def describe_snapshots(self, **_kwargs):
            return {"Snapshots": [{"State": "error"}]}

    ec2 = BadVerify()
    with pytest.raises(RuntimeError, match="snapshot verification"):
        run(ec2)
    assert ec2.calls[-1] == ("modify", {"InstanceId": "i-123", "Groups": ["sg-original"]})


def test_snapshot_failure_rolls_back_original_group():
    ec2 = EC2()
    ec2.fail_snapshot = True
    with pytest.raises(RuntimeError, match="snapshot error"):
        run(ec2)
    assert ec2.calls[-1][1]["Groups"] == ["sg-original"]
