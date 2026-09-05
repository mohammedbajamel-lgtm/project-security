from remediation.rollback_registry import rollback_for


def handle_failure(action, pre_state, handlers):
    name = rollback_for(action)
    if name is None:
        return {"status": "ESCALATED", "reason": "rollback_not_applicable"}
    try:
        return {"status": "ROLLED_BACK", "result": handlers[name](pre_state)}
    except Exception as exc:
        return {"status": "ESCALATED", "reason": "rollback_failed", "error": str(exc)}
