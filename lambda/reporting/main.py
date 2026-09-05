"""Generate and deliver terminal incident reports."""

import json
import os

import boto3
from common.logger import log_invocation

from reporting.json_report_generator import generate_json_report
from reporting.markdown_report_generator import generate_markdown_report


def _incident_from_event(event):
    detail = event.get("detail") or {}
    incident = detail.get("incident") or detail
    if not isinstance(incident, dict):
        raise ValueError("terminal event must contain an incident object")
    if detail.get("verification") and not incident.get("verification"):
        incident = {**incident, "verification": detail["verification"]}
    return incident


@log_invocation("incident-reporting")
def lambda_handler(event, context, *, s3_client=None, sns_client=None):
    """Create JSON/Markdown reports, store both, and notify stakeholders."""
    bucket = os.environ["EVIDENCE_BUCKET_NAME"]
    key_arn = os.environ["EVIDENCE_KEY_ARN"]
    topic_arn = os.environ["REPORTS_TOPIC_ARN"]
    report = generate_json_report(_incident_from_event(event))
    incident_id = report["incident_id"]
    prefix = f"evidence/{incident_id}/reports"
    s3 = s3_client or boto3.client("s3")
    sns = sns_client or boto3.client("sns")

    objects = {
        f"{prefix}/incident_report.json": (
            json.dumps(report, indent=2, sort_keys=True, default=str),
            "application/json",
        ),
        f"{prefix}/incident_report.md": (generate_markdown_report(report), "text/markdown"),
    }
    for key, (body, content_type) in objects.items():
        s3.put_object(
            Bucket=bucket,
            Key=key,
            Body=body.encode("utf-8"),
            ContentType=content_type,
            ServerSideEncryption="aws:kms",
            SSEKMSKeyId=key_arn,
        )

    sns.publish(
        TopicArn=topic_arn,
        Subject=f"CloudSec incident report: {incident_id}"[:100],
        Message=report["executive_summary"],
        MessageAttributes={
            "incident_id": {"DataType": "String", "StringValue": incident_id},
            "status": {"DataType": "String", "StringValue": str(report["status"])},
            "severity": {"DataType": "String", "StringValue": str(report["severity"])},
        },
    )
    return {"incident_id": incident_id, "report_keys": sorted(objects), "notified": True}
