"""Bounded, structured queries for relevant verified incidents."""

from boto3.dynamodb.conditions import Key

from knowledge_base.redactor import redact_incident_data


def _score(item, incident):
    reconstruction = incident.get("reconstruction") or {}
    stages = reconstruction.get("attack_stages") or []
    techniques = set(reconstruction.get("mitre_techniques") or [])
    investigation = incident.get("investigation_report") or {}
    return (
        (3 if item.get("attack_stage") in stages else 0)
        + (2 if techniques.intersection(item.get("mitre_techniques") or []) else 0)
        + (1 if item.get("root_cause_category") == investigation.get("root_cause_category") else 0)
    )


def query_knowledge_base(incident_data, table, *, limit=5):
    reconstruction = incident_data.get("reconstruction") or {}
    candidates = {}
    queries = []
    stages = reconstruction.get("attack_stages") or []
    techniques = reconstruction.get("mitre_techniques") or []
    if stages:
        queries.append(("attack_stage-index", Key("attack_stage").eq(stages[0])))
    if techniques:
        queries.append(("mitre_technique-index", Key("mitre_technique").eq(techniques[0])))
    for index_name, condition in queries:
        response = table.query(IndexName=index_name, KeyConditionExpression=condition, Limit=limit)
        for item in response.get("Items", []):
            candidates[(item["incident_id"], item["ingested_at"])] = item
    ranked = sorted(candidates.values(), key=lambda item: _score(item, incident_data), reverse=True)
    return [redact_incident_data(item) for item in ranked[: min(limit, 5)]]


def format_knowledge_context(entries):
    if not entries:
        return ""
    lines = []
    for item in entries[:5]:
        summary = (
            f"stage={item.get('attack_stage', 'UNKNOWN')}; "
            f"techniques={','.join(item.get('mitre_techniques') or [])}; "
            f"root_cause={item.get('root_cause_category', 'UNKNOWN')}; "
            f"actions={','.join(item.get('remediation_actions') or [])}"
        )
        lines.append(f"Previous Incident: {summary}")
    return "\n".join(lines)
