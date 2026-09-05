"""Safety boundary and shared utilities for Phase 18 simulations."""

from __future__ import annotations

import argparse
import json
import os
import time
import uuid
from datetime import UTC, datetime

import boto3

LAB_ACCOUNT = os.environ.get("CLOUDSEC_LAB_ACCOUNT_ID", "")
PREFIX = "cloudsec-lab-"
TAGS = [
    {"Key": "Environment", "Value": "lab"},
    {"Key": "Isolation", "Value": "strict"},
    {"Key": "Project", "Value": "cloudsec-ai"},
]


def parser(description):
    result = argparse.ArgumentParser(description=description)
    result.add_argument("--lab", action="store_true", help="required lab confirmation")
    result.add_argument("--cleanup", action="store_true")
    result.add_argument("--dry-run", action="store_true")
    result.add_argument("--region", default="us-east-1")
    return result


def guard(args):
    print("=" * 72)
    print("SIMULATION — NOT A REAL ATTACK")
    print("=" * 72)
    if not args.lab:
        raise SystemExit("Refusing to run without --lab")
    if len(LAB_ACCOUNT) != 12 or not LAB_ACCOUNT.isdigit():
        raise SystemExit("Set CLOUDSEC_LAB_ACCOUNT_ID to the intended 12-digit lab account")
    account = boto3.client("sts", region_name=args.region).get_caller_identity()["Account"]
    if account != LAB_ACCOUNT:
        raise SystemExit(f"Refusing unexpected account {account}; expected {LAB_ACCOUNT}")
    return account


def name(kind):
    return f"{PREFIX}{kind}-{uuid.uuid4().hex[:10]}"


def tag_map(extra=None):
    result = {item["Key"]: item["Value"] for item in TAGS}
    result.update(extra or {})
    return result


def assert_lab_name(value):
    if not str(value).startswith(PREFIX):
        raise ValueError(f"unsafe resource name: {value}")


def audit(scenario, action, resource, region="us-east-1"):
    boto3.client("cloudwatch", region_name=region).put_metric_data(
        Namespace="CloudSec/LabSimulations",
        MetricData=[
            {
                "MetricName": "SimulationAction",
                "Value": 1,
                "Unit": "Count",
                "Dimensions": [
                    {"Name": "Scenario", "Value": scenario},
                    {"Name": "Action", "Value": action},
                ],
            }
        ],
    )
    print(
        json.dumps(
            {
                "scenario": scenario,
                "action": action,
                "resource": resource,
                "timestamp": int(time.time()),
            }
        )
    )


def dry_run(args, actions):
    if args.dry_run:
        print(json.dumps({"dry_run": True, "actions": actions}, indent=2))
        return True
    return False


def publish_practice_finding(scenario, region="us-east-1"):
    """Publish an explicitly synthetic Security Hub finding for lab validation."""
    finding_id = f"cloudsec-lab/{scenario}/{uuid.uuid4().hex}"
    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    finding = {
        "SchemaVersion": "2018-10-08",
        "Id": finding_id,
        "ProductArn": (f"arn:aws:securityhub:{region}:{LAB_ACCOUNT}:product/{LAB_ACCOUNT}/default"),
        "GeneratorId": f"cloudsec-lab/{scenario}",
        "AwsAccountId": LAB_ACCOUNT,
        "Types": ["Unusual Behaviors/Practice Simulation"],
        "CreatedAt": now,
        "UpdatedAt": now,
        "Severity": {"Label": "MEDIUM"},
        "Title": f"SIMULATION — NOT A REAL ATTACK: {scenario}",
        "Description": "Harmless Phase 18 practice evidence generated after an isolated lab run.",
        "Resources": [{"Type": "Other", "Id": f"cloudsec-lab-{scenario}"}],
        "Workflow": {"Status": "NEW"},
        "RecordState": "ACTIVE",
    }
    result = boto3.client("securityhub", region_name=region).batch_import_findings(
        Findings=[finding]
    )
    if result.get("FailedCount"):
        raise RuntimeError(result["FailedFindings"])
    print(json.dumps({"scenario": scenario, "finding_id": finding_id, "synthetic": True}))
    return finding_id
