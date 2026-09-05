from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Any

from .time_window import group_sliding

SCANNERS = {"71.6.135.131", "162.142.125.0"}


def load_aws_networks(path: str | None = None) -> list[ipaddress._BaseNetwork]:
    source = Path(path) if path else Path(__file__).parents[2] / "docs" / "aws-ip-ranges.json"
    if not source.exists():
        return []
    data = json.loads(source.read_text(encoding="utf-8"))
    return [ipaddress.ip_network(row["ip_prefix"]) for row in data.get("prefixes", [])]


def correlate_by_ip(
    findings: list[Any], window_minutes: int = 30, aws_networks: list | None = None
) -> list[dict]:
    networks = load_aws_networks() if aws_networks is None else aws_networks

    def safe_ip(finding: Any) -> str | None:
        value = finding.source_ip
        if not value or value in SCANNERS:
            return None
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return None
        return None if any(address in network for network in networks) else value

    return [
        {"correlation_type": "source_ip", "findings": group}
        for group in group_sliding(findings, safe_ip, window_minutes)
    ]
