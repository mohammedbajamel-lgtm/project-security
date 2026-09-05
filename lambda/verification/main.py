"""EventBridge entry point for post-remediation verification."""

from __future__ import annotations

import os

import boto3
from common.logger import log_invocation

from verification.finding_rechecker import recheck_findings
from verification.resolution_engine import resolve_or_escalate
from verification.state_checker import (
    verify_cloudtrail_logging,
    verify_ec2_isolated,
    verify_iam_key_disabled,
    verify_policy_detached,
    verify_s3_public_blocked,
    verify_sg_ingress_revoked,
)


def _state_check(action, params, result, clients):
    if action == "disable_iam_key":
        return verify_iam_key_disabled(clients["iam"], params["user_name"], params["access_key_id"])
    if action == "revoke_security_group_ingress":
        return verify_sg_ingress_revoked(
            clients["ec2"], params["group_id"], params["cidr"], params["from_port"]
        )
    if action == "block_s3_public_access":
        return verify_s3_public_blocked(clients["s3"], params["bucket_name"])
    if action == "isolate_ec2_instance":
        return verify_ec2_isolated(
            clients["ec2"],
            params["instance_id"],
            result["isolation_group_id"],
            result["snapshot_ids"],
        )
    if action == "enable_cloudtrail_logging":
        return verify_cloudtrail_logging(
            clients["cloudtrail"], result.get("trail_name", params["trail_name"])
        )
    if action == "detach_privilege_escalation_policy":
        return verify_policy_detached(
            clients["iam"], params["role_arn"].rsplit("/", 1)[-1], params["policy_arn"]
        )
    raise ValueError("unknown remediation action")


@log_invocation("verification-engine")
def lambda_handler(event, _context):
    detail = event["detail"]
    names = ("iam", "ec2", "s3", "cloudtrail", "guardduty", "securityhub")
    clients = {name: boto3.client(name) for name in names}
    state = _state_check(detail["action"], detail["params"], detail.get("result", {}), clients)
    containment = recheck_findings(
        detail.get("findings", []),
        guardduty=clients["guardduty"],
        securityhub=clients["securityhub"],
        cloudtrail=clients["cloudtrail"],
        allow_preverified=os.environ.get("ENV_CODE") == "lab",
    )
    verification = {
        "state_checks": [state],
        "containment": containment,
        "no_new_findings": not detail.get("new_findings", []),
    }
    incident = {
        **detail["incident"],
        "investigation_report": detail.get(
            "investigation_report", detail["incident"].get("investigation_report", {})
        ),
        "blast_radius_report": detail.get(
            "blast_radius_report", detail["incident"].get("blast_radius_report", {})
        ),
    }
    table = boto3.resource("dynamodb").Table(os.environ["INCIDENTS_TABLE_NAME"])
    return resolve_or_escalate(
        table,
        boto3.client("events"),
        boto3.client("sns"),
        incident,
        verification,
        topic_arn=os.environ["ESCALATIONS_TOPIC_ARN"],
        event_bus_name=os.environ["SECURITY_BUS_NAME"],
    )
