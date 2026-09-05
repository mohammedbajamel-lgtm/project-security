def score(resources: list[dict], roles: list[dict], allowed_actions: list[str]) -> dict:
    factors = []
    value = sum(
        {"critical": 2, "high": 1, "medium": 0.5, "low": 0}.get(x["level"], 0) for x in resources
    )
    if any(x.get("privilege_level") == "admin" for x in roles):
        value += 3
        factors.append("admin_role_reachable")
    if any(x.get("cross_account") for x in roles):
        value += 2
        factors.append("cross_account_role_reachable")
    value += len(allowed_actions) // 10
    critical = sum(x["level"] == "critical" for x in resources)
    high = sum(x["level"] == "high" for x in resources)
    if critical:
        factors.append(f"critical_resources:{critical}")
    if high:
        factors.append(f"high_resources:{high}")
    value = min(10.0, float(value))
    level = (
        "CRITICAL" if value >= 8 else "HIGH" if value >= 5 else "MEDIUM" if value >= 3 else "LOW"
    )
    return {"risk_score": value, "risk_level": level, "top_risk_factors": factors[:3]}
