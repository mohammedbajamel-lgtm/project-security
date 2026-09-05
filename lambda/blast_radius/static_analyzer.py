"""Conservative static IAM policy fallback."""


def static_analyze(statements: list[dict]) -> dict:
    allowed, denied, conditions = set(), set(), set()
    for statement in statements:
        actions = statement.get("Action", [])
        actions = [actions] if isinstance(actions, str) else actions
        conditions.update(statement.get("Condition", {}).keys())
        (denied if statement.get("Effect") == "Deny" else allowed).update(actions)
    allowed -= denied
    return {
        "explicitly_allowed": sorted(allowed),
        "explicitly_denied": sorted(denied),
        "conditions": sorted(conditions),
        "analysis_method": "static",
        "confidence": "medium",
    }
