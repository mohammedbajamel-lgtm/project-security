"""AWS Lambda entry point for Phase 4 correlation."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import boto3
from common.dynamodb.findings_repo import FindingsRepository
from common.logger import log_invocation
from shared.incident_state import IncidentsRepository

from .correlation_engine import correlate_findings, persist_incidents


@log_invocation("correlation")
def lambda_handler(event, context):
    detail = event.get("detail", event)
    anchor = datetime.fromisoformat(detail["ingested_at"].replace("Z", "+00:00"))
    repo = FindingsRepository()
    findings = repo.get_findings_in_window(
        (anchor - timedelta(minutes=60)).isoformat(),
        (anchor + timedelta(minutes=60)).isoformat(),
    )
    incidents = correlate_findings(findings)
    stored = persist_incidents(
        incidents, IncidentsRepository(), boto3.client("events"), os.environ["SECURITY_BUS_NAME"]
    )
    return {"incidents_created": len(stored), "processed_at": datetime.now(UTC).isoformat()}
