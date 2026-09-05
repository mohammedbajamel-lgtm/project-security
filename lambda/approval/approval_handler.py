"""Defense-in-depth request router for the approval REST API."""

from __future__ import annotations

import json
import os

import boto3
from common.logger import log_invocation

from approval import decision_manager
from approval.stepfunctions_callback import send_callback


def _groups(event):
    claims = event.get("requestContext", {}).get("authorizer", {}).get("claims", {})
    return set(filter(None, claims.get("cognito:groups", "").split(",")))


def _principal(event):
    claims = event["requestContext"]["authorizer"]["claims"]
    return claims.get("custom:principal_arn") or claims["sub"]


def _public(value):
    if isinstance(value, dict):
        return {key: _public(item) for key, item in value.items() if key != "callback_token"}
    if isinstance(value, list):
        return [_public(item) for item in value]
    return value


def handle_request(event, *, manager, table, callback):
    method = event.get("httpMethod")
    decision_id = (event.get("pathParameters") or {}).get("decision_id")
    groups = _groups(event)
    if method == "POST" and "cloudsec_approver" not in groups:
        return {"statusCode": 403, "body": '{"error":"forbidden"}'}
    if method == "GET" and not groups & {"cloudsec_approver", "cloudsec_viewer"}:
        return {"statusCode": 403, "body": '{"error":"forbidden"}'}
    try:
        if method == "GET" and decision_id:
            result = manager.get_decision(table, decision_id)
        elif method == "GET":
            result = table.scan(
                Limit=min(int((event.get("queryStringParameters") or {}).get("limit", 25)), 100)
            )
        elif event["resource"].endswith("/approve"):
            result = manager.approve_decision(table, decision_id, _principal(event))
            callback(result, approved=True)
        else:
            reason = json.loads(event.get("body") or "{}").get("reason", "")
            result = manager.reject_decision(table, decision_id, _principal(event), reason)
            callback(result, approved=False)
        return {"statusCode": 200, "body": json.dumps(_public(result), default=str)}
    except (ValueError, PermissionError) as exc:
        return {"statusCode": 400, "body": json.dumps({"error": str(exc)})}


@log_invocation("approval-handler")
def lambda_handler(event, _context):
    table = boto3.resource("dynamodb").Table(os.environ["APPROVAL_TABLE_NAME"])
    if event.get("mode") == "register":
        return decision_manager.create_pending_decision(
            table,
            event["decision"],
            callback_token=event["task_token"],
        )
    stepfunctions = boto3.client("stepfunctions")

    def callback(decision, approved):
        send_callback(stepfunctions, decision, approved=approved)

    return handle_request(
        event,
        manager=decision_manager,
        table=table,
        callback=callback,
    )
