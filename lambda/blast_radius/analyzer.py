"""Phase 8 bounded blast-radius calculations."""

from __future__ import annotations

from typing import Any

MAX_RESOURCES = 1000


def analyze(
    findings: list[dict[str, Any]], *, max_resources: int = MAX_RESOURCES
) -> dict[str, Any]:
    principals = sorted({x["principal_arn"] for x in findings if x.get("principal_arn")})
    resources = sorted({x["resource_arn"] for x in findings if x.get("resource_arn")})
    accounts = sorted({x["account_id"] for x in findings if x.get("account_id")})
    regions = sorted({x["region"] for x in findings if x.get("region")})
    truncated = len(resources) > max_resources
    bounded = resources[:max_resources]
    return {
        "affected_principals": principals,
        "affected_resources": bounded,
        "affected_accounts": accounts,
        "affected_regions": regions,
        "resource_count": len(resources),
        "truncated": truncated,
        "risk_level": _risk(len(principals), len(resources), len(accounts)),
    }


def _risk(principals: int, resources: int, accounts: int) -> str:
    score = principals + resources + (accounts * 5)
    if score >= 25:
        return "CRITICAL"
    if score >= 10:
        return "HIGH"
    if score >= 3:
        return "MEDIUM"
    return "LOW"
