"""Recursive sensitive-data redaction with fail-closed helpers."""

import re

from knowledge_base.redaction_patterns import PATTERNS

COMPILED_PATTERNS = tuple(
    (label, re.compile(pattern, re.IGNORECASE)) for label, pattern in PATTERNS
)


class RedactionError(ValueError):
    """Raised when data cannot be safely redacted."""


def redact_for_bedrock(text):
    if not isinstance(text, str):
        raise RedactionError("redaction input must be text")
    result = text
    try:
        for label, pattern in COMPILED_PATTERNS:
            result = pattern.sub(f"[REDACTED_{label}]", result)
    except Exception as exc:
        raise RedactionError("redaction failed; Bedrock input blocked") from exc
    return result


def _redact_nested(value):
    if isinstance(value, str):
        return redact_for_bedrock(value)
    if isinstance(value, dict):
        return {key: _redact_nested(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_nested(item) for item in value]
    if value is None or isinstance(value, bool | int | float):
        return value
    raise RedactionError(f"unsupported value type: {type(value).__name__}")


def redact_incident_data(incident_data):
    return _redact_nested(incident_data)


def redact_finding_data(finding):
    return _redact_nested(finding)


def redact_evidence(evidence):
    return _redact_nested(evidence)
