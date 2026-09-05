from __future__ import annotations

from typing import Any

from .time_window import group_sliding


def correlate_by_principal(
    findings: list[Any], window_minutes: int = 15, cross_account_correlation: bool = False
) -> list[dict]:
    aliases: list[set[str]] = []
    for finding in findings:
        values = {finding.principal_arn, *finding.details.get("assumed_role_chain", [])}
        values.discard(None)
        overlaps = [group for group in aliases if group & values]
        merged = values.union(*overlaps)
        aliases = [group for group in aliases if group not in overlaps]
        aliases.append(merged)

    def key(finding: Any) -> str:
        account = "" if cross_account_correlation else finding.source_account
        identity = next((min(group) for group in aliases if finding.principal_arn in group), None)
        return f"{identity}|{account}" if identity else ""

    return [
        {"correlation_type": "principal_arn", "findings": group}
        for group in group_sliding(findings, key, window_minutes)
    ]
