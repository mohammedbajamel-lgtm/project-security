"""Read-only AWS state verifiers."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta


def _result(verified, actual, expected, now=None):
    return {
        "verified": bool(verified),
        "actual_state": actual,
        "expected_state": expected,
        "verification_time": (now or datetime.now(UTC)).isoformat(),
    }


def verify_iam_key_disabled(iam, user_name, key_id, *, now=None):
    try:
        keys = iam.list_access_keys(UserName=user_name).get("AccessKeyMetadata", [])
        status = next((key["Status"] for key in keys if key["AccessKeyId"] == key_id), "Missing")
        return _result(status in {"Inactive", "Missing"}, status, "Inactive", now)
    except Exception as exc:
        return _result(False, {"error": str(exc)}, "Inactive", now)


def verify_sg_ingress_revoked(ec2, group_id, cidr, port, *, now=None):
    try:
        rules = ec2.describe_security_group_rules(
            Filters=[{"Name": "group-id", "Values": [group_id]}]
        ).get("SecurityGroupRules", [])
        present = any(
            not rule.get("IsEgress")
            and (rule.get("CidrIpv4") == cidr or rule.get("CidrIpv6") == cidr)
            and rule.get("FromPort", -1) <= port <= rule.get("ToPort", -1)
            for rule in rules
        )
        return _result(not present, {"matching_rule_present": present}, "rule absent", now)
    except Exception as exc:
        return _result(False, {"error": str(exc)}, "rule absent", now)


def verify_s3_public_blocked(s3, bucket_name, *, now=None):
    try:
        config = s3.get_public_access_block(Bucket=bucket_name)["PublicAccessBlockConfiguration"]
        fields = (
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        )
        return _result(
            all(config.get(field) is True for field in fields),
            config,
            "all four controls true",
            now,
        )
    except Exception as exc:
        return _result(False, {"error": str(exc)}, "all four controls true", now)


def verify_ec2_isolated(ec2, instance_id, isolation_group_id, snapshot_ids, *, now=None):
    try:
        instance = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0][
            "Instances"
        ][0]
        groups = [group["GroupId"] for group in instance.get("SecurityGroups", [])]
        snapshots = ec2.describe_snapshots(SnapshotIds=snapshot_ids).get("Snapshots", [])
        states = [snapshot["State"] for snapshot in snapshots]
        good = (
            groups == [isolation_group_id]
            and len(states) == len(snapshot_ids)
            and all(state in {"pending", "completed"} for state in states)
        )
        return _result(
            good,
            {"groups": groups, "snapshot_states": states},
            {"groups": [isolation_group_id], "snapshot_states": ["pending|completed"]},
            now,
        )
    except Exception as exc:
        return _result(False, {"error": str(exc)}, "isolated with valid snapshots", now)


def verify_cloudtrail_logging(cloudtrail, trail_name, *, now=None):
    clock = now or datetime.now(UTC)
    try:
        status = cloudtrail.get_trail_status(Name=trail_name)
        latest = status.get("LatestDeliveryTime")
        recent = latest is not None and clock - latest <= timedelta(minutes=15)
        return _result(
            status.get("IsLogging") and recent, status, "logging with recent delivery", clock
        )
    except Exception as exc:
        return _result(False, {"error": str(exc)}, "logging with recent delivery", clock)


def verify_policy_detached(iam, role_name, policy_arn, *, now=None):
    try:
        policies = iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])
        present = policy_arn in {policy["PolicyArn"] for policy in policies}
        return _result(not present, {"policy_attached": present}, "policy detached", now)
    except Exception as exc:
        return _result(False, {"error": str(exc)}, "policy detached", now)
