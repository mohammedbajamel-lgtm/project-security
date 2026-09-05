"""Validated dispatcher for the six predefined remediation playbooks."""

import json
import os
from datetime import UTC, datetime

import boto3
from common.logger import log_invocation
from common.operational_metrics import emit_metric

from remediation.playbooks.block_s3_public_access import block_public_access
from remediation.playbooks.detach_privilege_policy import detach_policy
from remediation.playbooks.disable_iam_key import disable_key
from remediation.playbooks.fix_cloudtrail import fix_cloudtrail
from remediation.playbooks.isolate_ec2 import isolate_instance
from remediation.playbooks.revoke_sg_ingress import revoke_ingress
from remediation.state_machine_input import validate_input


def _execute(decision, clients=None):
    params = decision["params"]
    evidence = decision.get("evidence", {})
    approved = decision["level"] == 1 or bool(decision.get("human_approval_id"))
    clients = clients or {}

    def client(name):
        return clients.get(name) or boto3.client(name)

    action = decision["action"]
    if action == "disable_iam_key":
        return disable_key(client("iam"), approved=approved, evidence=evidence, **params)
    if action == "revoke_security_group_ingress":
        return revoke_ingress(client("ec2"), approved=approved, evidence=evidence, **params)
    if action == "block_s3_public_access":
        return block_public_access(client("s3"), approved=approved, evidence=evidence, **params)
    if action == "isolate_ec2_instance":
        return isolate_instance(
            client("ec2"),
            incident_id=decision["incident_id"],
            env=os.environ["ENV_CODE"],
            approved=approved,
            evidence=evidence,
            **params,
        )
    if action == "enable_cloudtrail_logging":
        return fix_cloudtrail(client("cloudtrail"), approved=approved, evidence=evidence, **params)
    if action == "detach_privilege_escalation_policy":
        return detach_policy(client("iam"), approved=approved, evidence=evidence, **params)
    raise ValueError("unknown remediation action")


def _finish(decision, status, *, result=None, error=None):
    incident = decision.get("incident") or {}
    incident_id = decision.get("incident_id")
    if incident and incident_id:
        table = boto3.resource("dynamodb").Table(os.environ["INCIDENTS_TABLE_NAME"])
        table.update_item(
            Key={"incident_id": incident_id, "event_time": incident["event_time"]},
            UpdateExpression="SET #s=:status, changed_at=:changed",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":status": status,
                ":changed": datetime.now(UTC).isoformat(),
            },
        )
    detail_type = "RemediationExecuted" if status == "VERIFYING" else "RemediationFailed"
    detail = {
        "incident_id": incident_id,
        "incident": {**incident, "status": status} if incident else {},
        "action": decision.get("action"),
        "params": decision.get("params", {}),
        "findings": decision.get("findings", []),
        "investigation_report": decision.get("investigation_report", {}),
        "blast_radius_report": decision.get("blast_radius_report", {}),
        "result": result or {},
        "error": error,
    }
    entries = [
        {
            "Source": "cloudsec.remediation",
            "DetailType": detail_type,
            "EventBusName": os.environ["SECURITY_BUS_NAME"],
            "Detail": json.dumps(detail, default=str),
        }
    ]
    if status == "ESCALATED" and incident:
        entries.append(
            {
                "Source": "cloudsec.remediation",
                "DetailType": "IncidentEscalated",
                "EventBusName": os.environ["SECURITY_BUS_NAME"],
                "Detail": json.dumps(
                    {
                        "incident_id": incident_id,
                        "status": status,
                        "incident": {**incident, "status": status},
                        "investigation_report": decision.get("investigation_report", {}),
                        "blast_radius_report": decision.get("blast_radius_report", {}),
                        "verification_results": {
                            "status": status,
                            "conditions": {},
                            "workflow_error": error,
                        },
                    },
                    default=str,
                ),
            }
        )
    boto3.client("events").put_events(Entries=entries)
    return {"handled": status, "decision": decision, "result": result or {}}


@log_invocation("remediation-framework")
def lambda_handler(event, _context, *, metrics=None):
    mode = event.get("mode")
    decision = event.get("decision", event)
    if mode == "validate":
        return {"valid": True, "decision": validate_input(decision)}
    if mode == "execute":
        validate_input(decision)
        try:
            result = _execute(decision)
            emit_metric(
                "RemediationExecuted",
                dimensions={"action": decision["action"]},
                client=metrics,
            )
            return {"decision": decision, "result": result}
        except Exception:
            emit_metric(
                "RemediationFailed",
                dimensions={"action": decision["action"]},
                client=metrics,
            )
            raise
    if mode == "success":
        return _finish(decision, "VERIFYING", result=event.get("result"))
    if mode == "failure":
        return _finish(decision, "ESCALATED", error=event.get("error"))
    if mode == "unlock":
        return {"handled": mode, "decision": decision}
    raise ValueError("unknown framework mode")
