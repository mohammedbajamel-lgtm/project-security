from __future__ import annotations

from typing import Any


def validate_citations(report: dict[str, Any], package: dict[str, Any]) -> list[str]:
    evidence = {item["evidence_id"]: item for item in package["evidence"]}
    cited_findings, errors = set(), []
    for citation in report["evidence_citations"]:
        item = evidence.get(citation["evidence_id"])
        if not item:
            errors.append(f"unknown evidence_id {citation['evidence_id']}")
        elif citation["quote"] not in str(item["content"]):
            errors.append(f"quote mismatch for {citation['evidence_id']}")
        else:
            cited_findings.add(item["finding_id"])
    missing = {item["finding_id"] for item in evidence.values()} - cited_findings
    return errors + [f"uncited finding {value}" for value in sorted(missing)]
