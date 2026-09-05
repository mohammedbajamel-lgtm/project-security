"""Investigation-report schema validation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema


class SchemaValidationError(ValueError):
    pass


def validate_report(report: str | dict[str, Any], schema: dict[str, Any] | None = None):
    try:
        value = json.loads(report) if isinstance(report, str) else report
    except json.JSONDecodeError as exc:
        raise SchemaValidationError(f"invalid JSON: {exc.msg}") from exc
    schema = schema or json.loads(
        (Path(__file__).parents[2] / "schemas" / "investigation-report-schema.json").read_text()
    )
    errors = sorted(
        jsonschema.Draft202012Validator(schema).iter_errors(value),
        key=lambda error: list(error.path),
    )
    if errors:
        details = [
            f"{'.'.join(map(str, error.path)) or '<root>'}: {error.message}" for error in errors
        ]
        raise SchemaValidationError("; ".join(details))
    return value
