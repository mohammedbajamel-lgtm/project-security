"""Sliding-window grouping shared by correlators."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any


def timestamp(finding: Any) -> datetime:
    raw = finding.finding_time or finding.ingested_at
    return datetime.fromisoformat(raw.replace("Z", "+00:00"))


def group_sliding(
    findings: list[Any], key: Callable[[Any], str | None], minutes: int
) -> list[list[Any]]:
    groups: list[list[Any]] = []
    by_key: dict[str, list[Any]] = {}
    for finding in findings:
        value = key(finding)
        if value:
            by_key.setdefault(value, []).append(finding)
    delta = timedelta(minutes=minutes)
    for candidates in by_key.values():
        ordered = sorted(candidates, key=timestamp)
        current: list[Any] = []
        for finding in ordered:
            if current and timestamp(finding) - timestamp(current[-1]) > delta:
                if len(current) >= 2:
                    groups.append(current)
                current = []
            current.append(finding)
        if len(current) >= 2:
            groups.append(current)
    return groups
