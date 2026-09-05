"""Capture only the resource configurations named by investigation evidence."""

from datetime import UTC, datetime

from evidence.writer import put_json


def capture_config_snapshot(
    clients, bucket, incident_id, resources, kms_key_id, actor, *, now=None
):
    snapshot = {
        "incident_id": incident_id,
        "captured_at": (now or datetime.now(UTC)).isoformat(),
        "capture_actor": actor,
        "resources": [],
    }
    for resource in resources:
        kind = resource["type"]
        if kind == "iam_user":
            value = clients["iam"].get_user(UserName=resource["name"])["User"]
            value["attached_policies"] = clients["iam"].list_attached_user_policies(
                UserName=resource["name"]
            )["AttachedPolicies"]
        elif kind == "iam_role":
            value = clients["iam"].get_role(RoleName=resource["name"])["Role"]
        elif kind == "s3_bucket":
            s3 = clients["s3"]
            value = {
                "policy": s3.get_bucket_policy(Bucket=resource["name"])["Policy"],
                "public_access_block": s3.get_public_access_block(Bucket=resource["name"])[
                    "PublicAccessBlockConfiguration"
                ],
            }
        elif kind == "ec2_instance":
            value = clients["ec2"].describe_instances(InstanceIds=[resource["id"]])
        elif kind == "security_group":
            value = clients["ec2"].describe_security_group_rules(
                Filters=[{"Name": "group-id", "Values": [resource["id"]]}]
            )
        elif kind == "cloudtrail":
            value = clients["cloudtrail"].get_trail_status(Name=resource["name"])
        else:
            raise ValueError(f"unsupported resource type: {kind}")
        snapshot["resources"].append(
            {
                "type": kind,
                "identifier": resource.get("name", resource.get("id")),
                "configuration": value,
            }
        )
    put_json(
        s3=clients["s3"],
        bucket=bucket,
        key=f"evidence/{incident_id}/pre_remediation_config.json",
        value=snapshot,
        kms_key_id=kms_key_id,
    )
    return snapshot
