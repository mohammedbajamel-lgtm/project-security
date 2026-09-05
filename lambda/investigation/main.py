"""Phase 6 investigation Lambda entrypoint."""

from __future__ import annotations

import json
import os
from pathlib import Path

import boto3
from blast_radius.analyzer import analyze
from common.logger import log_invocation
from reconstruction.orchestrator import reconstruct_attack

from investigation.bedrock_investigator import investigate
from investigation.evidence_packager import package_evidence


def _config(ssm) -> dict:
    prefix = f"/cloudsec/{os.environ['ENV_CODE']}/ai/"
    names = [prefix + key for key in ("model_id", "max_tokens", "temperature", "retry_max")]
    values = ssm.get_parameters(Names=names, WithDecryption=False)["Parameters"]
    mapped = {item["Name"].removeprefix(prefix): item["Value"] for item in values}
    return {
        "model_id": mapped["model_id"],
        "max_tokens": int(mapped.get("max_tokens", 4096)),
        "temperature": float(mapped.get("temperature", 0)),
        "retry_max": int(mapped.get("retry_max", 3)),
    }


@log_invocation("investigation")
def lambda_handler(event, _context, *, dynamodb=None, events=None, ssm=None):
    detail = event.get("detail", event)
    incident = detail.get("incident", detail)
    incident_id = incident["incident_id"]
    dynamodb = dynamodb or boto3.resource("dynamodb")
    events = events or boto3.client("events")
    ssm = ssm or boto3.client("ssm")

    findings = detail.get("finding_records", detail.get("findings", []))
    reconstruction = detail.get("reconstruction") or reconstruct_attack(findings)
    blast_radius = detail.get("blast_radius") or analyze(findings)
    package = package_evidence(
        incident,
        findings,
        correlations=detail.get("correlations"),
        baselines=detail.get("baselines"),
        reconstruction=reconstruction,
        blast_radius=blast_radius,
    )
    schema = json.loads((Path(__file__).with_name("report_schema.json")).read_text())
    report = investigate(package, schema, _config(ssm))
    report["incident_id"] = incident_id
    table = dynamodb.Table(os.environ["INCIDENTS_TABLE_NAME"])
    table.update_item(
        Key={"incident_id": incident_id, "event_time": incident["event_time"]},
        UpdateExpression="SET investigation_report = :report, investigation_status = :status",
        ExpressionAttributeValues={
            ":report": report,
            ":status": report["validation_status"],
        },
    )
    event_type = (
        "InvestigationCompleted"
        if report["validation_status"] == "ACCEPTED"
        else "InvestigationRejected"
    )
    events.put_events(
        Entries=[
            {
                "Source": "cloudsec.investigation",
                "DetailType": event_type,
                "Detail": json.dumps(
                    {
                        "incident_id": incident_id,
                        "incident": incident,
                        "findings": findings,
                        "reconstruction": reconstruction,
                        "blast_radius": blast_radius,
                        "report": report,
                    }
                ),
                "EventBusName": os.environ["SECURITY_BUS_NAME"],
            }
        ]
    )
    return report
