"""Restore an evidence-backed CloudTrail trail without weakening its configuration."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta


def _trail(cloudtrail, name: str) -> dict | None:
    trails = cloudtrail.describe_trails(trailNameList=[name], includeShadowTrails=False).get(
        "trailList", []
    )
    return trails[0] if trails else None


def fix_cloudtrail(
    cloudtrail,
    trail_name: str,
    *,
    approved: bool,
    evidence: dict,
    now: datetime | None = None,
) -> dict:
    if not approved:
        raise PermissionError("approved safety decision required")
    if evidence.get("trail_name") != trail_name:
        raise PermissionError("trail is not supported by investigation evidence")
    clock = now or datetime.now(UTC)
    trail = _trail(cloudtrail, trail_name)
    recreated = False
    if trail is None:
        try:
            deleted_at = datetime.fromisoformat(evidence["deleted_at"].replace("Z", "+00:00"))
            original = evidence["previous_configuration"]
        except (KeyError, TypeError, ValueError) as exc:
            raise PermissionError("deleted trail configuration evidence is incomplete") from exc
        if not clock - timedelta(hours=24) <= deleted_at <= clock:
            raise PermissionError("trail was not deleted within the last 24 hours")
        new_name = f"{trail_name}-recreated-{clock.strftime('%Y%m%d%H%M%S')}"
        create = {
            "Name": new_name,
            "S3BucketName": original["S3BucketName"],
            "IncludeGlobalServiceEvents": original.get("IncludeGlobalServiceEvents", True),
            "IsMultiRegionTrail": original.get("IsMultiRegionTrail", True),
            "EnableLogFileValidation": True,
        }
        for key in ("S3KeyPrefix", "SnsTopicName", "KmsKeyId", "IsOrganizationTrail"):
            if key in original:
                create[key] = original[key]
        trail = cloudtrail.create_trail(**create)
        trail_name = new_name
        recreated = True

    status = cloudtrail.get_trail_status(Name=trail_name)
    pre_state = {
        "trail": dict(trail),
        "is_logging": status.get("IsLogging", False),
        "log_file_validation": trail.get("LogFileValidationEnabled", False),
    }
    if not trail.get("LogFileValidationEnabled", False):
        cloudtrail.update_trail(Name=trail_name, EnableLogFileValidation=True)
    if not status.get("IsLogging", False):
        cloudtrail.start_logging(Name=trail_name)

    verified = _trail(cloudtrail, trail_name)
    verified_status = cloudtrail.get_trail_status(Name=trail_name)
    expected_bucket = evidence.get("s3_bucket", trail.get("S3BucketName"))
    if (
        not verified
        or not verified_status.get("IsLogging")
        or not verified.get("LogFileValidationEnabled")
        or verified.get("S3BucketName") != expected_bucket
    ):
        raise RuntimeError("CloudTrail post-verification failed")
    return {
        "changed": recreated
        or not pre_state["is_logging"]
        or not pre_state["log_file_validation"],
        "status": "LOGGING",
        "trail_name": trail_name,
        "pre_remediation_state": pre_state,
    }
