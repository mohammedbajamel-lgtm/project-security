from datetime import UTC, datetime, timedelta

STAGES = {
    "STARTED",
    "LOCK_ACQUIRED",
    "PLAYBOOK_INVOKED",
    "PLAYBOOK_SUCCEEDED",
    "PLAYBOOK_FAILED",
    "VERIFICATION_STARTED",
    "VERIFICATION_PASSED",
    "VERIFICATION_FAILED",
    "COMPLETED",
    "ESCALATED",
    "ROLLBACK_STARTED",
    "ROLLBACK_SUCCEEDED",
    "ROLLBACK_FAILED",
}


def log_execution_event(table, execution_id, event, *, now=None):
    if event["stage"] not in STAGES:
        raise ValueError("invalid audit stage")
    current = now or datetime.now(UTC)
    item = {
        **event,
        "execution_id": execution_id,
        "event_time": current.isoformat(),
        "expires_at": int((current + timedelta(days=400)).timestamp()),
    }
    table.put_item(
        Item=item,
        ConditionExpression=(
            "attribute_not_exists(execution_id) AND attribute_not_exists(event_time)"
        ),
    )
    return item
