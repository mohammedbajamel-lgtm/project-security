def pre_execution_hook(incident, decision, resource_state):
    failures = []
    if incident.get("status") != "REMEDIATING":
        failures.append("incident_not_remediating")
    if not decision.get("valid", False):
        failures.append("decision_invalid")
    if not resource_state.get("exists", False):
        failures.append("resource_missing")
    if not resource_state.get("vulnerable", False):
        failures.append("state_not_vulnerable")
    return {"passed": not failures, "failures": failures, "pre_remediation_state": resource_state}


def post_execution_hook(resource_state):
    failures = []
    if not resource_state.get("exists", False):
        failures.append("resource_missing")
    if not resource_state.get("secure", False):
        failures.append("secure_state_not_observed")
    if resource_state.get("unexpected_side_effects"):
        failures.append("unexpected_side_effects")
    return {"passed": not failures, "failures": failures}
