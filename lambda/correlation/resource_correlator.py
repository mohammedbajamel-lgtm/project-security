from __future__ import annotations

from typing import Any

from .time_window import group_sliding


def normalize_arn(value: str | None) -> str | None:
    if not value or "*" in value:
        return None
    parts = value.rstrip("/").split(":", 5)
    if len(parts) != 6 or parts[0].lower() != "arn":
        return None
    parts[0] = "arn"
    parts[2] = parts[2].lower()
    if parts[2] in {"iam", "s3", "route53", "cloudfront"}:
        parts[3] = ""
    return ":".join(parts)


def correlate_by_resource(findings: list[Any], window_minutes: int = 60) -> list[dict]:
    return [
        {"correlation_type": "resource_arn", "findings": group}
        for group in group_sliding(
            findings, lambda f: normalize_arn(f.resource_arn), window_minutes
        )
    ]
