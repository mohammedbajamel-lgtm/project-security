"""Phase 4 correlation acceptance tests."""

from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import boto3
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lambda"))

from common.dynamodb.findings_repo import Finding, FindingsRepository
from correlation.incident_builder import assign_findings, build_incident
from correlation.ip_correlator import correlate_by_ip
from correlation.principal_correlator import correlate_by_principal
from correlation.resource_correlator import correlate_by_resource, normalize_arn
from correlation.tie_breaker import winner
from correlation.time_window import group_sliding

BASE = datetime(2026, 9, 4, tzinfo=UTC)


def finding(identifier, minutes=0, **kwargs):
    stamp = (BASE + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z")
    return Finding(
        identifier,
        stamp,
        source_account=kwargs.pop("account", "111111111111"),
        finding_time=stamp,
        **kwargs,
    )


def test_principal_window_cross_account_and_singletons():
    values = [
        finding("a", principal_arn="p"),
        finding("b", 14, principal_arn="p"),
        finding("c", 40, principal_arn="p"),
        finding("d", 5, principal_arn="p", account="222222222222"),
    ]
    assert [len(g["findings"]) for g in correlate_by_principal(values)] == [2]
    assert len(correlate_by_principal(values, cross_account_correlation=True)[0]["findings"]) == 3


def test_role_chain_and_overlapping_windows_merge():
    values = [
        finding("a", principal_arn="role", details={"assumed_role_chain": ["user"]}),
        finding("b", 10, principal_arn="user"),
        finding("c", 20, principal_arn="user"),
    ]
    assert len(correlate_by_principal(values)[0]["findings"]) == 3
    assert len(group_sliding(values, lambda row: "same", 15)[0]) == 3


def test_ip_exclusions_and_distinct_ips():
    network = __import__("ipaddress").ip_network("10.0.0.0/8")
    values = [
        finding("a", source_ip="8.8.8.8"),
        finding("b", 1, source_ip="8.8.8.8"),
        finding("c", source_ip="10.0.0.1"),
        finding("d", 1, source_ip="10.0.0.1"),
        finding("e", source_ip=None),
    ]
    groups = correlate_by_ip(values, aws_networks=[network])
    assert [[f.finding_id for f in group["findings"]] for group in groups] == [["a", "b"]]


def test_resource_normalization_and_wildcard_exclusion():
    assert normalize_arn("ARN:AWS:IAM::123:role/admin/") == "arn:AWS:iam::123:role/admin"
    values = [
        finding("a", resource_arn="arn:aws:s3:::bucket"),
        finding("b", 2, resource_arn="arn:aws:s3:::bucket/"),
        finding("c", resource_arn="arn:aws:s3:::*"),
    ]
    assert len(correlate_by_resource(values)[0]["findings"]) == 2


def test_assignment_severity_tie_break_and_deterministic_incident():
    a, b = finding("a", severity="P2"), finding("b", severity="P1")
    groups = [
        {"correlation_type": "source_ip", "findings": [a, b]},
        {"correlation_type": "principal_arn", "findings": [a, b]},
    ]
    assigned = assign_findings(groups)
    assert len(assigned) == 1 and assigned[0]["correlation_type"] == "principal_arn"
    incident = build_incident(assigned[0])
    assert incident["severity"] == "P1" and incident["finding_count"] == 2
    assert build_incident(assigned[0])["incident_id"] == incident["incident_id"]
    assert winner([a, b]) == b


@mock_aws
def test_findings_repository_all_indexes_and_scan():
    client = boto3.client("dynamodb", region_name="us-east-1")
    definitions = [
        {"AttributeName": name, "AttributeType": "S"}
        for name in (
            "finding_id",
            "ingested_at",
            "principal_arn",
            "source_ip",
            "resource_arn",
            "source_account",
        )
    ]
    gsis = [
        {
            "IndexName": index,
            "KeySchema": [
                {"AttributeName": field, "KeyType": "HASH"},
                {"AttributeName": "ingested_at", "KeyType": "RANGE"},
            ],
            "Projection": {"ProjectionType": "ALL"},
        }
        for index, field in (
            ("principal-index", "principal_arn"),
            ("source-ip-index", "source_ip"),
            ("resource-index", "resource_arn"),
            ("account-index", "source_account"),
        )
    ]
    client.create_table(
        TableName="findings",
        KeySchema=[
            {"AttributeName": "finding_id", "KeyType": "HASH"},
            {"AttributeName": "ingested_at", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=definitions,
        GlobalSecondaryIndexes=gsis,
        BillingMode="PAY_PER_REQUEST",
    )
    table = boto3.resource("dynamodb", region_name="us-east-1").Table("findings")
    table.put_item(
        Item={
            "finding_id": "a",
            "ingested_at": "2026-09-04T00:00:00Z",
            "principal_arn": "p",
            "source_ip": "8.8.8.8",
            "resource_arn": "r",
            "source_account": "111",
        }
    )
    repo = FindingsRepository(table=table, table_name="findings")
    start, end = "2026-09-03T00:00:00Z", "2026-09-05T00:00:00Z"
    assert repo.get_findings_by_principal("p", start, end)[0].finding_id == "a"
    assert repo.get_findings_by_source_ip("8.8.8.8", start, end)
    assert repo.get_findings_by_resource("r", start, end)
    assert repo.get_findings_by_account("111", start, end)
    assert repo.get_findings_in_window(start, end)
