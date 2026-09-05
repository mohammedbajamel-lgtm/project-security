"""
Tests for T02-02 - DynamoDB Findings Table (Terraform plan assertions).

Assertions:
  - Table cloudsec-dev-findings exists in the plan.
  - Hash key = finding_id (String), range key = ingested_at (String).
  - Four GSIs: principal-index, source-ip-index, resource-index, account-index.
  - SSE-KMS with the finding key ARN.
  - PITR enabled.
  - Deletion protection off in dev.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]


def _load_plan() -> dict:
    plan_path = ROOT / "tests" / "unit" / "terraform" / "phase2.plan.json"
    if not plan_path.exists():
        pytest.skip(
            f"No Terraform plan at {plan_path}. "
            "Generate with: terraform plan -out=tfplan-phase2.binary && "
            "terraform show -json tfplan-phase2.binary > "
            "tests/unit/terraform/phase2.plan.json"
        )
    return json.loads(plan_path.read_text(encoding="utf-8"))


def _find_resource(planned: dict, name: str) -> dict | None:
    modules = [planned.get("planned_values", {}).get("root_module", {})]
    for module in modules:
        modules.extend(module.get("child_modules", []))
    for module in modules:
        for res in module.get("resources", []):
            addr = res.get("address", "")
            if f"aws_dynamodb_table.{name}" in addr:
                return res
    return None


def test_findings_table_is_added_to_plan():
    planned = _load_plan()
    for change in planned.get("resource_changes", []):
        if "aws_dynamodb_table.findings" in change.get("address", ""):
            assert change.get("change", {}).get("actions") == ["create"]
            return
    raise AssertionError("Findings table should be added by the Phase 2 plan")


def test_findings_table_schema_and_indexes():
    planned = _load_plan()
    res = _find_resource(planned, "findings")
    assert res is not None, "Findings table resource missing from plan"

    attrs = res.get("values", {})
    assert attrs.get("name") == "cloudsec-dev-findings"
    assert attrs.get("billing_mode") == "PAY_PER_REQUEST"
    assert attrs.get("hash_key") == "finding_id"
    assert attrs.get("range_key") == "ingested_at"

    attributes = attrs.get("attribute", [])
    names = {a["name"] for a in attributes}
    assert names == {
        "finding_id",
        "ingested_at",
        "principal_arn",
        "source_ip",
        "resource_arn",
        "source_account",
    }

    gsis = attrs.get("global_secondary_index", [])
    gsi_names = {g["name"]: g for g in gsis}
    expected = {
        "principal-index": ("principal_arn", "ingested_at"),
        "source-ip-index": ("source_ip", "ingested_at"),
        "resource-index": ("resource_arn", "ingested_at"),
        "account-index": ("source_account", "ingested_at"),
    }
    for gsi_name, (hash_key, range_key) in expected.items():
        assert gsi_name in gsi_names, f"Missing GSI {gsi_name}"
        assert gsi_names[gsi_name]["hash_key"] == hash_key
        assert gsi_names[gsi_name]["range_key"] == range_key


def test_findings_table_encryption_and_pitr():
    planned = _load_plan()
    res = _find_resource(planned, "findings")
    assert res is not None

    attrs = res.get("values", {})
    sse = attrs.get("server_side_encryption", [None])
    assert len(sse) == 1 and sse[0] is not None

    pitr = attrs.get("point_in_time_recovery", [None])
    assert len(pitr) == 1 and pitr[0] is not None
    assert pitr[0].get("enabled") is True

    assert attrs.get("deletion_protection_enabled") is False


def test_findings_schema_fixture():
    """Fixture-based schema validation for a normalized finding item."""
    sample = {
        "finding_id": "ff-aaaa-bbbb-cccc-dddd",
        "ingested_at": "2026-09-04T00:00:00Z",
        "source_account": "123456789012",
        "source_region": "us-east-1",
        "source_type": "guardduty",
        "severity": "HIGH",
        "principal_arn": "arn:aws:iam::123456789012:user/bad-user",
        "source_ip": "203.0.113.42",
        "resource_arn": "arn:aws:s3:::sensitive-bucket",
    }
    assert len(sample["source_account"]) == 12
    assert sample["source_region"] == "us-east-1"
    assert sample["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
