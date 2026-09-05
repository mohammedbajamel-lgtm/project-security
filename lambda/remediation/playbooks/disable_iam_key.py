"""Disable, never delete, a compromised IAM access key."""

from __future__ import annotations

from botocore.exceptions import ClientError


def _key(iam, user_name, access_key_id):
    paginator = iam.get_paginator("list_access_keys")
    for page in paginator.paginate(UserName=user_name):
        for metadata in page.get("AccessKeyMetadata", []):
            if metadata["AccessKeyId"] == access_key_id:
                return metadata
    return None


def disable_key(iam, user_name: str, access_key_id: str, *, approved: bool, evidence: dict) -> dict:
    if not approved:
        raise PermissionError("approved safety decision required")
    if evidence.get("user_name") != user_name or evidence.get("access_key_id") != access_key_id:
        raise PermissionError("key is not supported by investigation evidence")
    if not evidence.get("cloudtrail_used", False):
        raise PermissionError("CloudTrail does not support suspicious key use")
    metadata = _key(iam, user_name, access_key_id)
    if metadata is None:
        raise ValueError("access key not found")
    pre_state = {
        "user_name": user_name,
        "access_key_id": access_key_id,
        "status": metadata["Status"],
        "last_used": evidence.get("last_used"),
    }
    if metadata["Status"] == "Inactive":
        return {"changed": False, "status": "Inactive", "pre_remediation_state": pre_state}
    try:
        iam.update_access_key(UserName=user_name, AccessKeyId=access_key_id, Status="Inactive")
        updated = _key(iam, user_name, access_key_id)
        if not updated or updated["Status"] != "Inactive":
            raise RuntimeError("post-verification failed")
    except Exception:
        try:
            iam.update_access_key(UserName=user_name, AccessKeyId=access_key_id, Status="Active")
        except ClientError:
            pass
        raise
    return {
        "changed": True,
        "status": "Inactive",
        "pre_remediation_state": pre_state,
        "audit": {
            "key_id": access_key_id,
            "user_name": user_name,
            "previous_status": "Active",
            "new_status": "Inactive",
        },
    }
