"""EventBridge entry point for verified incident knowledge ingestion."""

import os

import boto3
from common.logger import log_invocation

from knowledge_base.kb_ingestor import ingest_resolved_incident


@log_invocation("knowledge-base-ingestor")
def lambda_handler(event, context, *, dynamodb=None):
    detail = event.get("detail") or {}
    incident = detail.get("incident") or detail
    table = (dynamodb or boto3.resource("dynamodb")).Table(os.environ["KNOWLEDGE_BASE_TABLE_NAME"])
    return ingest_resolved_incident(incident, table)
