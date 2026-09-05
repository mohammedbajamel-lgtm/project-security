"""Validated Bedrock investigation orchestration; never executes actions."""

from __future__ import annotations

import json
from typing import Any

from common.bedrock_client import invoke_bedrock

from investigation.citation_validator import validate_citations
from investigation.hallucination_checker import check_hallucinations
from investigation.prompt_builder import build_prompt
from investigation.schema_validator import SchemaValidationError, validate_report


def investigate(
    package: dict[str, Any],
    schema: dict[str, Any],
    config: dict[str, Any],
    *,
    invoker=invoke_bedrock,
) -> dict[str, Any]:
    prompt = build_prompt(package, schema)
    last_error = None
    for _ in range(int(config.get("retry_max", 3)) + 1):
        try:
            response = invoker(
                prompt,
                config["model_id"],
                int(config["max_tokens"]),
                float(config.get("temperature", 0)),
            )
            content = response.get("content", [])
            text = content[0]["text"] if content else response.get("completion", "")
            report = validate_report(text, schema)
            errors = validate_citations(report, package) + check_hallucinations(report, package)
            if errors:
                return {**report, "validation_status": "REJECTED", "validation_errors": errors}
            return {**report, "validation_status": "ACCEPTED"}
        except (SchemaValidationError, json.JSONDecodeError, KeyError) as exc:
            last_error = exc
            prompt += "\nYour previous response was invalid. Return corrected JSON only."
    raise SchemaValidationError(f"Bedrock report validation exhausted: {last_error}")
