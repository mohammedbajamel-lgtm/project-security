"""AWS-aware Phase 19 E2E harness with strict lab guardrails."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import boto3
import pytest
from boto3.dynamodb.conditions import Key

from tests.e2e.test_config import (
    LAB_ACCOUNT_ID,
    REQUIRED_SSM_KEYS,
    SCENARIO_CONFIGS,
    SCENARIO_TIMEOUT_SECONDS,
    SSM_PREFIX,
)


@dataclass
class E2ETestRunner:
    region: str = "us-east-1"
    expected_account_id: str = LAB_ACCOUNT_ID
    dry_run: bool = False
    session: Any = None
    config: dict[str, str] = field(default_factory=dict)
    tracked_items: list[tuple[str, dict]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.session = self.session or boto3.Session(region_name=self.region)
        actual = self.session.client("sts").get_caller_identity()["Account"]
        if actual != self.expected_account_id:
            raise RuntimeError(
                f"E2E account mismatch: expected {self.expected_account_id}, got {actual}"
            )
        self.config = self._load_config()
        self._validate_config()

    def _load_config(self) -> dict[str, str]:
        paginator = self.session.client("ssm").get_paginator("get_parameters_by_path")
        values = {}
        for page in paginator.paginate(Path=SSM_PREFIX, Recursive=True, WithDecryption=True):
            for parameter in page["Parameters"]:
                values[parameter["Name"].removeprefix(SSM_PREFIX)] = parameter["Value"]
        return values

    def _validate_config(self) -> None:
        missing = REQUIRED_SSM_KEYS - self.config.keys()
        if missing:
            raise RuntimeError(f"Missing E2E SSM parameters: {', '.join(sorted(missing))}")
        if self.config["account_id"] != self.expected_account_id:
            raise RuntimeError("SSM account_id does not match the validated caller")
        if self.config["environment"] != "lab" or self.config["resource_prefix"] != "cloudsec-lab":
            raise RuntimeError("E2E configuration is not the isolated cloudsec-lab environment")
        resource_keys = {
            "findings_table",
            "incidents_table",
            "decisions_table",
            "approval_decisions_table",
            "idempotency_table",
            "remediation_audit_table",
            "event_bus",
            "evidence_bucket",
            "guardduty_function",
            "securityhub_function",
        }
        invalid = [key for key in resource_keys if not self.config[key].startswith("cloudsec-lab-")]
        if invalid:
            raise RuntimeError(
                f"Non-lab resources in E2E configuration: {', '.join(sorted(invalid))}"
            )
        if int(self.config["scenario_timeout_seconds"]) > SCENARIO_TIMEOUT_SECONDS:
            raise RuntimeError("E2E scenario timeout exceeds the 10-minute safety limit")

    def run_test(self, scenario_name: str) -> dict[str, Any]:
        if scenario_name not in SCENARIO_CONFIGS:
            raise KeyError(f"Unknown E2E scenario: {scenario_name}")
        return {
            "scenario": scenario_name,
            "dry_run": self.dry_run,
            "configuration": SCENARIO_CONFIGS[scenario_name],
        }

    def cleanup(self) -> None:
        # Cleanup is deliberately limited to exact keys registered by this run.
        dynamodb = self.session.resource("dynamodb")
        for table_name, key in reversed(self.tracked_items):
            if not table_name.startswith("cloudsec-lab-"):
                raise RuntimeError("Refusing cleanup outside cloudsec-lab")
            if not self.dry_run:
                dynamodb.Table(table_name).delete_item(Key=key)
        self.tracked_items.clear()

    def _latest_incident(self, incident_id: str) -> dict[str, Any]:
        table = self.session.resource("dynamodb").Table(self.config["incidents_table"])
        items = table.query(KeyConditionExpression=Key("incident_id").eq(incident_id))["Items"]
        if not items:
            raise AssertionError(f"Incident {incident_id} was not found")
        return max(items, key=lambda item: item["event_time"])

    def assert_incident_resolved(self, incident_id: str) -> dict[str, Any]:
        incident = self._latest_incident(incident_id)
        assert incident["status"] == "RESOLVED"
        return incident

    def assert_incident_escalated(self, incident_id: str) -> dict[str, Any]:
        incident = self._latest_incident(incident_id)
        assert incident["status"] == "ESCALATED"
        return incident

    @staticmethod
    def wait_for_event(probe, timeout: int = SCENARIO_TIMEOUT_SECONDS, interval: float = 2.0):
        deadline = time.monotonic() + min(timeout, SCENARIO_TIMEOUT_SECONDS)
        while time.monotonic() < deadline:
            value = probe()
            if value:
                return value
            time.sleep(interval)
        raise TimeoutError("Timed out waiting for E2E event")


@pytest.mark.e2e_live
def test_harness_validates_lab_and_loads_all_scenarios(e2e_runner):
    assert e2e_runner.config["account_id"] == LAB_ACCOUNT_ID
    assert e2e_runner.config["resource_prefix"] == "cloudsec-lab"
    assert len(SCENARIO_CONFIGS) == 12
    for scenario in SCENARIO_CONFIGS:
        result = e2e_runner.run_test(scenario)
        assert result["scenario"] == scenario
