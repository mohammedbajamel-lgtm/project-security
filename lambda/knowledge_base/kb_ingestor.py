"""Ingest only successfully resolved incidents into the structured knowledge base."""

from datetime import UTC, datetime

from botocore.exceptions import ClientError

from knowledge_base.redactor import redact_incident_data


def build_record(incident, *, ingested_at=None):
    if incident.get("status") != "RESOLVED":
        raise ValueError("only RESOLVED incidents may enter the knowledge base")
    reconstruction = incident.get("reconstruction") or {}
    investigation = incident.get("investigation_report") or {}
    actions = incident.get("actions_taken") or []
    techniques = reconstruction.get("mitre_techniques") or ["UNKNOWN"]
    stages = reconstruction.get("attack_stages") or ["UNKNOWN"]
    record = {
        "incident_id": incident["incident_id"],
        "ingested_at": ingested_at
        or incident.get("resolved_at")
        or incident.get("created_at")
        or datetime.now(UTC).isoformat(),
        "attack_stage": stages[0],
        "mitre_technique": techniques[0],
        "mitre_techniques": techniques,
        "remediation_action": actions[0].get("action", "NONE") if actions else "NONE",
        "remediation_actions": [item.get("action", "UNKNOWN") for item in actions],
        "timeline_pattern": reconstruction.get("timeline_summary", "No timeline summary"),
        "resolution_success": True,
        "blast_radius_risk_score": (incident.get("blast_radius_report") or {}).get("risk_score", 0),
        "root_cause_category": investigation.get("root_cause_category", "UNKNOWN"),
    }
    return redact_incident_data(record)


def ingest_resolved_incident(incident, table, *, ingested_at=None):
    record = build_record(incident, ingested_at=ingested_at)
    try:
        table.put_item(
            Item=record,
            ConditionExpression=(
                "attribute_not_exists(incident_id) AND attribute_not_exists(ingested_at)"
            ),
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return {"ingested": False, "duplicate": True, "record": record}
        raise
    return {"ingested": True, "duplicate": False, "record": record}
