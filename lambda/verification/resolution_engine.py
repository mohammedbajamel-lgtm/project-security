"""Fail-closed incident resolution decision."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from common.operational_metrics import emit_metric


def resolve_or_escalate(
    table,
    events,
    sns,
    incident: dict,
    verification: dict,
    *,
    topic_arn: str,
    event_bus_name: str | None = None,
    metrics=None,
    now=None,
):
    clock = now or datetime.now(UTC)
    conditions = {
        "state_verified": all(
            check.get("verified") is True for check in verification.get("state_checks", [])
        )
        and bool(verification.get("state_checks")),
        "containment_confirmed": verification.get("containment", {}).get("contained") is True,
        "no_new_findings": verification.get("no_new_findings") is True,
    }
    resolved = all(conditions.values())
    status = "RESOLVED" if resolved else "ESCALATED"
    result = {
        **verification,
        "conditions": conditions,
        "status": status,
        "decided_at": clock.isoformat(),
    }
    values = {":status": status, ":verification": result}
    expression = "SET #s=:status, verification=:verification"
    if resolved:
        values[":resolved"] = clock.isoformat()
        values[":duration"] = int(
            (clock - datetime.fromisoformat(incident["created_at"])).total_seconds()
        )
        expression += ", resolved_at=:resolved, time_to_resolve_seconds=:duration"
    event_time = incident.get("event_time")
    if not event_time:
        raise ValueError("incident event_time is required for an atomic update")
    table.update_item(
        Key={"incident_id": incident["incident_id"], "event_time": event_time},
        UpdateExpression=expression,
        ConditionExpression="#s=:verifying",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={**values, ":verifying": "VERIFYING"},
    )
    detail_type = "IncidentResolved" if resolved else "IncidentEscalated"
    events.put_events(
        Entries=[
            {
                **({"EventBusName": event_bus_name} if event_bus_name else {}),
                "Source": "cloudsec.verification",
                "DetailType": detail_type,
                "Detail": json.dumps(
                    {
                        "incident_id": incident["incident_id"],
                        "status": status,
                        "incident": incident,
                        "verification_results": result,
                    },
                    default=str,
                ),
            }
        ]
    )
    if not resolved:
        failures = [name for name, passed in conditions.items() if not passed]
        sns.publish(
            TopicArn=topic_arn,
            Message=json.dumps(
                {
                    "incident_id": incident["incident_id"],
                    "severity": incident.get("severity"),
                    "verification_failures": failures,
                    "containment_status": conditions["containment_confirmed"],
                }
            ),
        )
    emit_metric("VerificationPassed" if resolved else "VerificationFailed", client=metrics)
    emit_metric("IncidentResolved" if resolved else "IncidentEscalated", client=metrics)
    return result
