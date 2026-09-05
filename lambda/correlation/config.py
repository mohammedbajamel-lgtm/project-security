"""SSM-backed correlation configuration with a five-minute cache."""

from __future__ import annotations

import os
import time
from typing import Any

import boto3

DEFAULTS = {"principal": 15, "ip": 30, "resource": 60}
_cache: tuple[float, dict[str, int]] | None = None


def load_config(ssm: Any = None, now: float | None = None) -> dict[str, int]:
    global _cache
    current = time.monotonic() if now is None else now
    if _cache and current - _cache[0] < 300:
        return dict(_cache[1])
    client = ssm or boto3.client("ssm")
    env = os.getenv("ENV_CODE", "dev")
    config = dict(DEFAULTS)
    for kind in config:
        name = f"/cloudsec/{env}/correlation/{kind}_window_minutes"
        try:
            config[kind] = int(client.get_parameter(Name=name)["Parameter"]["Value"])
        except client.exceptions.ParameterNotFound:
            pass
    _cache = (current, config)
    return dict(config)


def clear_cache() -> None:
    global _cache
    _cache = None
