"""Typed, paginated access to the normalized findings table."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

import boto3
from boto3.dynamodb.conditions import Attr, Key
from boto3.dynamodb.types import TypeDeserializer
from shared.incident_state import dynamodb_retry


@dataclass(frozen=True)
class Finding:
    finding_id: str
    ingested_at: str
    source_account: str = ""
    source_region: str = ""
    source_type: str = ""
    severity: str = "P4"
    principal_arn: str | None = None
    source_ip: str | None = None
    resource_arn: str | None = None
    finding_time: str | None = None
    service: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_item(cls, item: dict[str, Any]) -> Finding:
        allowed = cls.__dataclass_fields__.keys()
        return cls(**{key: value for key, value in item.items() if key in allowed})


class FindingsRepository:
    def __init__(self, table=None, table_name: str | None = None):
        name = table_name or os.getenv("FINDINGS_TABLE_NAME") or os.getenv("FINDINGS_TABLE")
        if not name:
            raise ValueError("FINDINGS_TABLE_NAME environment variable is required")
        self.table = table or boto3.resource("dynamodb").Table(name)

    def _all_pages(self, **kwargs) -> list[Finding]:
        items: list[Finding] = []
        while True:
            response = (
                self.table.query(**kwargs) if "IndexName" in kwargs else self.table.scan(**kwargs)
            )
            items.extend(Finding.from_item(item) for item in response.get("Items", []))
            key = response.get("LastEvaluatedKey")
            if not key:
                return items
            kwargs["ExclusiveStartKey"] = key

    @dynamodb_retry()
    def _query(self, index: str, field: str, value: str, start: str, end: str) -> list[Finding]:
        return self._all_pages(
            IndexName=index,
            KeyConditionExpression=Key(field).eq(value) & Key("ingested_at").between(start, end),
        )

    def get_findings_by_principal(self, value: str, start: str, end: str) -> list[Finding]:
        return self._query("principal-index", "principal_arn", value, start, end)

    def get_findings_by_source_ip(self, value: str, start: str, end: str) -> list[Finding]:
        return self._query("source-ip-index", "source_ip", value, start, end)

    def get_findings_by_resource(self, value: str, start: str, end: str) -> list[Finding]:
        return self._query("resource-index", "resource_arn", value, start, end)

    def get_findings_by_account(self, value: str, start: str, end: str) -> list[Finding]:
        return self._query("account-index", "source_account", value, start, end)

    @dynamodb_retry()
    def get_findings_in_window(self, start: str, end: str, max_items: int = 1000) -> list[Finding]:
        result = self._all_pages(FilterExpression=Attr("ingested_at").between(start, end))
        return result[:max_items]


_DESERIALIZER = TypeDeserializer()


def deserialize_item(item: dict[str, Any]) -> dict[str, Any]:
    return {key: _DESERIALIZER.deserialize(value) for key, value in item.items()}
