"""Assemble and validate the canonical structured incident report."""

from datetime import UTC, datetime

from reporting.executive_summary import generate_executive_summary

REQUIRED = {"incident_id", "severity", "status", "created_at"}


def generate_json_report(incident, *, generated_at=None, platform_version="1.0"):
    missing = REQUIRED - set(incident)
    if missing:
        raise ValueError(f"missing report fields: {sorted(missing)}")
    investigation = incident.get("investigation_report") or {}
    reconstruction = incident.get("reconstruction") or {}
    report = {
        "incident_id": incident["incident_id"],
        "severity": incident["severity"],
        "status": incident["status"],
        "created_at": incident["created_at"],
        "resolved_at": incident.get("resolved_at"),
        "escalated_at": incident.get("escalated_at"),
        "time_to_resolve_seconds": incident.get("time_to_resolve_seconds"),
        "timeline": reconstruction.get("timeline", []),
        "root_cause": investigation.get("root_cause", "Not established"),
        "attack_stages_detected": reconstruction.get("attack_stages", []),
        "mitre_attack_techniques": reconstruction.get("mitre_techniques", []),
        "affected_principals": incident.get("affected_principals", []),
        "affected_resources": incident.get("affected_resources", []),
        "blast_radius": incident.get("blast_radius_report") or {},
        "actions_taken": incident.get("actions_taken", []),
        "evidence": incident.get("evidence") or {},
        "verification": incident.get("verification") or {},
        "recommendations": investigation.get("recommended_actions", []),
        "generated_at": (generated_at or datetime.now(UTC)).isoformat(),
        "platform_version": platform_version,
    }
    report["executive_summary"] = generate_executive_summary(
        {**incident, "recommendations": report["recommendations"]}
    )
    return report
