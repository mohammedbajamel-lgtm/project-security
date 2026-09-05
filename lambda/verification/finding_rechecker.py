"""Read-only re-checks for findings associated with an incident."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta


def recheck_findings(
    findings, *, guardduty, securityhub, cloudtrail, allow_preverified=False, now=None
):
    clock = now or datetime.now(UTC)
    results = []
    for finding in findings:
        source = finding["source"]
        if (
            allow_preverified
            and source == "lab_simulation"
            and finding.get("state_verified") is True
        ):
            contained = True
        elif source == "guardduty":
            item = guardduty.get_findings(
                DetectorId=finding["detector_id"], FindingIds=[finding["finding_id"]]
            ).get("Findings", [{}])[0]
            contained = (
                item.get("Service", {}).get("Archived", False)
                or item.get("RecordState") == "ARCHIVED"
            )
        elif source == "securityhub":
            item = securityhub.batch_get_findings(FindingIdentifiers=[finding["identifier"]]).get(
                "Findings", [{}]
            )[0]
            contained = (
                item.get("RecordState") == "ARCHIVED"
                or item.get("Compliance", {}).get("Status") == "PASSED"
            )
        elif source == "cloudtrail":
            events = cloudtrail.lookup_events(
                LookupAttributes=[
                    {"AttributeKey": "EventName", "AttributeValue": finding["event_name"]}
                ],
                StartTime=clock - timedelta(minutes=30),
                EndTime=clock,
            ).get("Events", [])
            contained = not events
        elif source == "s3_public_access":
            identifiers = finding.get("identifiers", [])
            items = (
                securityhub.batch_get_findings(FindingIdentifiers=identifiers).get("Findings", [])
                if identifiers
                else []
            )
            contained = bool(items) and (
                all(
                    result.get("RecordState") == "ARCHIVED"
                    or result.get("Compliance", {}).get("Status") == "PASSED"
                    for result in items
                )
            )
        else:
            contained = False
        results.append(
            {"finding_id": finding["finding_id"], "source": source, "contained": contained}
        )
    return {
        "contained": bool(results) and all(item["contained"] for item in results),
        "checks": results,
        "checked_at": clock.isoformat(),
    }
