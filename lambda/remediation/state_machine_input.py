from datetime import UTC, datetime

REQUIRED = {"decision_id", "incident_id", "action", "level", "params"}


def validate_input(value: dict, *, now=None) -> dict:
    missing = REQUIRED - set(value)
    if missing:
        raise ValueError(f"missing fields: {sorted(missing)}")
    if value["level"] not in {1, 2}:
        raise ValueError("only approved Level 1 or Level 2 decisions may execute")
    if value["level"] == 2 and not value.get("human_approval_id"):
        raise ValueError("Level 2 requires human approval")
    if value.get("expires_at") and datetime.fromisoformat(value["expires_at"]) <= (
        now or datetime.now(UTC)
    ):
        raise ValueError("decision expired")
    return value
