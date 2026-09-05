"""Safety validation Lambda: validates and publishes decisions, never remediates."""

from __future__ import annotations

import json
import os
from decimal import Decimal

import boto3
from common.logger import log_invocation

from safety.execution_engine import execute_validation


def _dynamodb_item(value):
    """Convert JSON numbers to DynamoDB-safe Decimal values without changing event output."""
    return json.loads(json.dumps(value), parse_float=Decimal)


def _execution_evidence(recommendation, report):
    evidence = dict(recommendation.get("params", {}))
    finding_type = report.get("finding_type")
    if finding_type == "PublicS3Bucket":
        evidence["publicly_exposed"] = True
    if finding_type in {"UnauthorizedAccess", "UnauthorizedAPI"}:
        evidence["compromised"] = True
        if report.get("cloudtrail_used"):
            evidence["cloudtrail_used"] = True
        if report.get("last_used"):
            evidence["last_used"] = report["last_used"]
    return evidence


@log_invocation("safety-validation")
def lambda_handler(event, _context, *, events=None, dynamodb=None):
    detail = event.get("detail", event)
    report = detail["report"]
    report["incident_id"] = detail["incident_id"]
    recommendations = report.get("recommended_actions", [])
    decisions = []
    for recommendation in recommendations:
        decision = execute_validation(recommendation, report)
        decision.update(
            params=recommendation.get("params", {}),
            evidence=_execution_evidence(recommendation, report),
            incident=detail.get("incident"),
            findings=detail.get("findings", []),
            investigation_report=report,
            blast_radius_report=detail.get("blast_radius", {}),
            affected_principals=[
                value.get("arn")
                for value in report.get("affected_principals", [])
                if value.get("arn")
            ],
        )
        decisions.append(decision)
    dynamodb = dynamodb or boto3.resource("dynamodb")
    table = dynamodb.Table(os.environ["DECISIONS_TABLE_NAME"])
    for decision in decisions:
        table.put_item(
            Item=_dynamodb_item(decision),
            ConditionExpression="attribute_not_exists(decision_id)",
        )
    events = events or boto3.client("events")
    events.put_events(
        Entries=[
            {
                "Source": "cloudsec.safety",
                "DetailType": decision["event_type"],
                "Detail": json.dumps(decision),
                "EventBusName": os.environ["SECURITY_BUS_NAME"],
            }
            for decision in decisions
        ]
    )
    return {"decisions": decisions}
