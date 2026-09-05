"""Package immutable evidence after an incident reaches a terminal state."""

from __future__ import annotations

import os

import boto3
from common.logger import log_invocation

from evidence.analysis_storage import store_analysis
from evidence.manifest_generator import generate_manifest
from evidence.remediation_history import store_remediation_history


@log_invocation("evidence-packager")
def lambda_handler(event, _context):
    detail = event["detail"]
    incident = detail["incident"]
    incident_id = incident["incident_id"]
    s3 = boto3.client("s3")
    bucket = os.environ["EVIDENCE_BUCKET_NAME"]
    kms_key = os.environ["EVIDENCE_KEY_ARN"]
    store_analysis(
        s3,
        bucket,
        incident_id,
        kms_key,
        detail.get("investigation_report") or incident.get("investigation_report", {}),
        detail.get("blast_radius_report") or incident.get("blast_radius_report", {}),
        detail["verification_results"],
    )
    audit = boto3.resource("dynamodb").Table(os.environ["REMEDIATION_AUDIT_TABLE_NAME"])
    history = store_remediation_history(
        s3,
        audit,
        boto3.client("stepfunctions"),
        bucket,
        incident_id,
        detail.get("execution_arns", []),
        kms_key,
    )
    manifest = generate_manifest(s3, bucket, incident_id, kms_key)
    incidents = boto3.resource("dynamodb").Table(os.environ["INCIDENTS_TABLE_NAME"])
    incidents.update_item(
        Key={"incident_id": incident_id, "event_time": incident["event_time"]},
        UpdateExpression=(
            "SET evidence_manifest_sha256=:hash, evidence_manifest_s3_key=:key, "
            "evidence_remediation_history_s3_key=:history"
        ),
        ExpressionAttributeValues={
            ":hash": manifest["overall_sha256"],
            ":key": f"evidence/{incident_id}/manifest.json",
            ":history": history["s3_key"],
        },
    )
    return {"incident_id": incident_id, "manifest": manifest}
