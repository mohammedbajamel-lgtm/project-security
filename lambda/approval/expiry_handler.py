"""Scheduled expiration of stale approval decisions."""

import json
import os

import boto3
from common.logger import log_invocation

from approval.decision_manager import expire_pending


@log_invocation("approval-expiry")
def lambda_handler(_event, _context):
    table = boto3.resource("dynamodb").Table(os.environ["APPROVAL_TABLE_NAME"])
    events = boto3.client("events")
    sns = boto3.client("sns")

    def escalate(decision):
        detail = {
            "incident_id": decision["incident_id"],
            "decision_id": decision["decision_id"],
            "reason": "approval_expired",
        }
        events.put_events(
            Entries=[
                {
                    "EventBusName": os.environ["SECURITY_BUS_NAME"],
                    "Source": "cloudsec.approval",
                    "DetailType": "RemediationApprovalTimedOut",
                    "Detail": json.dumps(detail),
                }
            ]
        )
        sns.publish(TopicArn=os.environ["ESCALATIONS_TOPIC_ARN"], Message=json.dumps(detail))

    expired = expire_pending(table, on_expired=escalate)
    return {"expired_count": len(expired)}
