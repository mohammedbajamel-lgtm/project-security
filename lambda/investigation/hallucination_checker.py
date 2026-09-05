from __future__ import annotations

import re
from typing import Any


def check_hallucinations(report: dict[str, Any], package: dict[str, Any]) -> list[str]:
    corpus = str(package["evidence"])
    errors = []
    for field in ("affected_principals", "affected_resources"):
        for item in report[field]:
            arn = item.get("arn")
            if arn and arn not in corpus:
                errors.append(f"unsupported ARN {arn}")
    for technique in report["mitre_attack_techniques"]:
        if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique):
            errors.append(f"invalid MITRE technique {technique}")
    if report["attack_stage"] == "exfiltration" and not any(
        word in corpus for word in ("GetObject", "PutObject", "transfer", "S3")
    ):
        errors.append("exfiltration is unsupported by evidence")
    return errors
