"""
Tests for T02-05 - Internal Event Schema Validation.

Loads each schema from schemas/, resolves $refs to common-types.json, and
validates one valid payload per event type. Also validates that each schema
is well-formed JSON Schema.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS_DIR = ROOT / "schemas"


def _load(schema_name: str) -> dict:
    path = SCHEMAS_DIR / schema_name
    if not path.exists():
        pytest.skip(f"Schema {schema_name} not found at {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _common_defs() -> dict:
    return _load("common-types.json")["$defs"]


def _resolve_in_place(obj: dict, common_defs: dict) -> dict:
    """Recursively resolve $ref pointing at ./common-types.json#/$defs/X.

    Replaces each $ref with the corresponding definition from common-types
    (which itself contains no cross-refs to other files at this depth).
    """
    if isinstance(obj, dict):
        if "$ref" in obj and obj["$ref"].startswith("./common-types.json#/$defs/"):
            ref_name = obj["$ref"].split("/")[-1]
            return copy.deepcopy(common_defs[ref_name])
        return {k: _resolve_in_place(v, common_defs) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_resolve_in_place(x, common_defs) for x in obj]
    return obj


def _validate(schema_name: str, payload: dict) -> None:
    """Load schema, resolve $refs, and validate payload. Raises on failure."""
    schema = _load(schema_name)
    common_defs = _common_defs()
    resolved_defs = _resolve_in_place(copy.deepcopy(schema.get("$defs", {})), common_defs)

    event_type = payload.get("event_type")
    if event_type and event_type in resolved_defs:
        target = resolved_defs[event_type]
    else:
        # Some schemas wrap payload via top-level $ref
        if "$ref" in schema and schema["$ref"].endswith("#/$defs/"):
            target_name = schema["$ref"].split("/")[-1]
            target = resolved_defs[target_name]
        else:
            target = {"type": "object", "allOf": list(resolved_defs.values())}
            target = resolved_defs[next(iter(resolved_defs))]

    validator = Draft202012Validator(target, format_checker=FormatChecker())
    validator.validate(payload)


# ---- Valid payloads ----


def _finding_ingested_payload() -> dict:
    return {
        "schema_version": "1.0.0",
        "event_id": "00000000-0000-4000-8000-000000000001",
        "event_type": "FindingIngested",
        "timestamp": "2026-09-04T00:00:00Z",
        "source_account": "123456789012",
        "source_region": "us-east-1",
        "source_type": "guardduty",
        "finding_id": "gd-aaaa-bbbb-cccc-dddd",
        "finding_time": "2026-09-04T00:00:00Z",
        "severity": "P2",
        "principal_arn": "arn:aws:iam::123456789012:user/bad-user",
        "resource_arn": "arn:aws:s3:::sensitive-bucket",
        "source_ip": "203.0.113.42",
        "service": "guardduty",
        "details": {"service_name": "UnauthorizedAccess"},
    }


def _incident_created_payload() -> dict:
    return {
        "schema_version": "1.0.0",
        "event_id": "00000000-0000-4000-8000-000000000002",
        "event_type": "IncidentCreated",
        "timestamp": "2026-09-04T00:00:00Z",
        "source_account": "123456789012",
        "source_region": "us-east-1",
        "incident_id": "00000000-0000-4000-8000-000000000003",
        "severity": "P2",
        "status": "OPEN",
        "finding_ids": ["gd-aaaa-bbbb-cccc-dddd"],
        "correlation_type": "principal_arn",
        "principal_arn": "arn:aws:iam::123456789012:user/bad-user",
        "resource_arn": "arn:aws:s3:::sensitive-bucket",
        "source_ip": "203.0.113.42",
        "created_at": "2026-09-04T00:00:00Z",
        "ttl": 9999999999,
        "window_start": "2026-09-04T00:00:00Z",
        "window_end": "2026-09-04T00:15:00Z",
        "version": 1,
    }


def _incident_status_changed_payload() -> dict:
    return {
        "schema_version": "1.0.0",
        "event_id": "00000000-0000-4000-8000-000000000004",
        "event_type": "IncidentStatusChanged",
        "timestamp": "2026-09-04T00:00:00Z",
        "incident_id": "00000000-0000-4000-8000-000000000003",
        "previous_status": "OPEN",
        "new_status": "INVESTIGATING",
        "reason": "Investigation engine started",
        "changed_by": "cloudsec-dev-investigation",
        "changed_at": "2026-09-04T00:00:00Z",
    }


def _investigation_started_payload() -> dict:
    return {
        "schema_version": "1.0.0",
        "event_id": "00000000-0000-4000-8000-000000000005",
        "event_type": "InvestigationStarted",
        "timestamp": "2026-09-04T00:00:00Z",
        "incident_id": "00000000-0000-4000-8000-000000000003",
        "started_at": "2026-09-04T00:00:00Z",
        "model": "anthropic.claude-3-5-sonnet-20241022-v2:0",
        "run_id": "00000000-0000-4000-8000-000000000006",
    }


def _remediation_executed_payload() -> dict:
    return {
        "schema_version": "1.0.0",
        "event_id": "00000000-0000-4000-8000-000000000007",
        "event_type": "RemediationExecuted",
        "timestamp": "2026-09-04T00:00:00Z",
        "incident_id": "00000000-0000-4000-8000-000000000003",
        "run_id": "00000000-0000-4000-8000-000000000008",
        "playbook_name": "iam-credential-compromise",
        "executed_at": "2026-09-04T00:00:00Z",
        "steps": [{"name": "disable-access-key", "status": "completed"}],
    }


def test_all_schemas_are_valid_json():
    for name in [
        "common-types.json",
        "finding-event.json",
        "incident-event.json",
        "investigation-event.json",
        "remediation-event.json",
    ]:
        schema = _load(name)
        assert isinstance(schema, dict)


def test_schemas_are_valid_json_schema():
    """Every schema must be a syntactically valid JSON Schema."""
    for name in [
        "common-types.json",
        "finding-event.json",
        "incident-event.json",
        "investigation-event.json",
        "remediation-event.json",
    ]:
        schema = _load(name)
        Draft202012Validator.check_schema(schema)


def test_finding_ingested_validates():
    _validate("finding-event.json", _finding_ingested_payload())


def test_incident_created_validates():
    _validate("incident-event.json", _incident_created_payload())


def test_incident_status_changed_validates():
    _validate("incident-event.json", _incident_status_changed_payload())


def test_investigation_started_validates():
    _validate("investigation-event.json", _investigation_started_payload())


def test_remediation_executed_validates():
    _validate("remediation-event.json", _remediation_executed_payload())


# ---- Rejection tests ----


def test_missing_required_field_rejected():
    payload = _incident_created_payload()
    payload.pop("incident_id")
    with pytest.raises(ValidationError):
        _validate("incident-event.json", payload)


def test_invalid_severity_rejected():
    payload = _finding_ingested_payload()
    payload["severity"] = "CRITICAL"  # Not in enum P1..P4
    with pytest.raises(ValidationError):
        _validate("finding-event.json", payload)


def test_invalid_status_rejected():
    payload = _incident_created_payload()
    payload["status"] = "UNKNOWN"
    with pytest.raises(ValidationError):
        _validate("incident-event.json", payload)


def test_bad_account_id_rejected():
    payload = _finding_ingested_payload()
    payload["source_account"] = "123"  # Not 12 digits
    with pytest.raises(ValidationError):
        _validate("finding-event.json", payload)


def test_bad_timestamp_rejected():
    payload = _finding_ingested_payload()
    payload["timestamp"] = "not-a-date"
    with pytest.raises(ValidationError):
        _validate("finding-event.json", payload)


def test_additional_properties_rejected():
    """Schema says additionalProperties=false; extra key must fail."""
    payload = _finding_ingested_payload()
    payload["unexpected_field"] = "hello"
    with pytest.raises(ValidationError):
        _validate("finding-event.json", payload)
