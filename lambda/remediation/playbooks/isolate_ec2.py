"""Isolate an approved compromised EC2 instance without terminating it."""

from __future__ import annotations


def _instance(ec2, instance_id: str) -> dict:
    response = ec2.describe_instances(InstanceIds=[instance_id])
    reservations = response.get("Reservations", [])
    instances = [item for reservation in reservations for item in reservation.get("Instances", [])]
    if not instances:
        raise ValueError("instance not found")
    return instances[0]


def _isolation_group(ec2, vpc_id: str, env: str) -> str:
    name = f"cloudsec-{env}-isolation-sg"
    existing = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": [name]},
        ]
    ).get("SecurityGroups", [])
    if existing:
        return existing[0]["GroupId"]
    group_id = ec2.create_security_group(
        GroupName=name,
        Description="CloudSec deny-all isolation security group",
        VpcId=vpc_id,
    )["GroupId"]
    group = ec2.describe_security_groups(GroupIds=[group_id])["SecurityGroups"][0]
    if group.get("IpPermissionsEgress"):
        ec2.revoke_security_group_egress(
            GroupId=group_id, IpPermissions=group["IpPermissionsEgress"]
        )
    return group_id


def isolate_instance(
    ec2,
    instance_id: str,
    incident_id: str,
    *,
    env: str,
    approved: bool,
    evidence: dict,
) -> dict:
    if not approved:
        raise PermissionError("approved safety decision required")
    if evidence.get("instance_id") != instance_id:
        raise PermissionError("instance is not supported by investigation evidence")
    instance = _instance(ec2, instance_id)
    if instance.get("State", {}).get("Name") != "running":
        raise ValueError("instance must be running")
    tags = {tag["Key"]: tag["Value"] for tag in instance.get("Tags", [])}
    if tags.get("cloudsec_no_isolate", "").lower() == "true":
        raise PermissionError("instance is explicitly excluded from isolation")

    original_groups = [group["GroupId"] for group in instance.get("SecurityGroups", [])]
    volumes = [
        mapping["Ebs"]["VolumeId"]
        for mapping in instance.get("BlockDeviceMappings", [])
        if "Ebs" in mapping
    ]
    pre_state = {
        "instance_id": instance_id,
        "state": "running",
        "security_group_ids": original_groups,
        "volume_ids": volumes,
    }
    isolation_group_id = _isolation_group(ec2, instance["VpcId"], env)
    if original_groups == [isolation_group_id]:
        return {"changed": False, "status": "VERIFYING", "pre_remediation_state": pre_state}

    try:
        ec2.modify_instance_attribute(InstanceId=instance_id, Groups=[isolation_group_id])
        snapshots = [
            ec2.create_snapshot(
                VolumeId=volume_id,
                Description=f"CloudSec incident {incident_id} forensic snapshot",
                TagSpecifications=[
                    {
                        "ResourceType": "snapshot",
                        "Tags": [
                            {"Key": "cloudsec_incident_id", "Value": incident_id},
                            {"Key": "SecurityStatus", "Value": "QUARANTINED"},
                        ],
                    }
                ],
            )["SnapshotId"]
            for volume_id in volumes
        ]
        ec2.create_tags(
            Resources=[instance_id],
            Tags=[
                {"Key": "SecurityStatus", "Value": "QUARANTINED"},
                {"Key": "cloudsec_incident_id", "Value": incident_id},
            ],
        )
        current = _instance(ec2, instance_id)
        current_groups = [
            group["GroupId"] for group in current.get("SecurityGroups", [])
        ]
        if current_groups != [isolation_group_id]:
            raise RuntimeError("isolation verification failed")
        described = ec2.describe_snapshots(SnapshotIds=snapshots)["Snapshots"]
        states = [item["State"] for item in described]
        if any(state not in {"pending", "completed"} for state in states):
            raise RuntimeError("snapshot verification failed")
    except Exception:
        ec2.modify_instance_attribute(InstanceId=instance_id, Groups=original_groups)
        raise
    return {
        "changed": True,
        "status": "VERIFYING",
        "isolation_group_id": isolation_group_id,
        "snapshot_ids": snapshots,
        "pre_remediation_state": pre_state,
    }
