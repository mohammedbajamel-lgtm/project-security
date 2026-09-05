"""Apply all S3 Block Public Access controls to one evidence-backed bucket."""

from __future__ import annotations

BLOCKED = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


def _error_code(exc: Exception) -> str | None:
    return getattr(exc, "response", {}).get("Error", {}).get("Code")


def _configuration(s3, bucket_name: str) -> dict | None:
    try:
        return s3.get_public_access_block(Bucket=bucket_name)["PublicAccessBlockConfiguration"]
    except Exception as exc:
        if _error_code(exc) == "NoSuchPublicAccessBlockConfiguration":
            return None
        raise


def _tags(s3, bucket_name: str) -> dict[str, str]:
    try:
        tag_set = s3.get_bucket_tagging(Bucket=bucket_name).get("TagSet", [])
    except Exception as exc:
        if _error_code(exc) == "NoSuchTagSet":
            return {}
        raise
    return {item["Key"]: item["Value"] for item in tag_set}


def block_public_access(s3, bucket_name: str, *, approved: bool, evidence: dict) -> dict:
    if not approved:
        raise PermissionError("approved safety decision required")
    if evidence.get("bucket_name") != bucket_name or not evidence.get("publicly_exposed"):
        raise PermissionError("bucket exposure is not supported by investigation evidence")

    s3.head_bucket(Bucket=bucket_name)
    if _tags(s3, bucket_name).get("intentional_public", "").lower() == "true":
        raise PermissionError("intentional public bucket requires escalation")
    previous = _configuration(s3, bucket_name)
    if previous == BLOCKED:
        return {
            "changed": False,
            "status": "BLOCKED",
            "pre_remediation_state": previous,
        }
    try:
        s3.put_public_access_block(
            Bucket=bucket_name, PublicAccessBlockConfiguration=BLOCKED
        )
        if _configuration(s3, bucket_name) != BLOCKED:
            raise RuntimeError("post-verification failed")
        s3.head_bucket(Bucket=bucket_name)
    except Exception:
        if previous is None:
            s3.delete_public_access_block(Bucket=bucket_name)
        else:
            s3.put_public_access_block(
                Bucket=bucket_name, PublicAccessBlockConfiguration=previous
            )
        raise
    return {
        "changed": True,
        "status": "BLOCKED",
        "pre_remediation_state": previous,
        "audit": {"bucket_name": bucket_name, "action": "block_public_access"},
    }
