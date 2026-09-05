"""Generate a cryptographic inventory of an incident evidence prefix."""

import hashlib
from datetime import UTC, datetime

from evidence.writer import put_json


def generate_manifest(s3, bucket, incident_id, kms_key_id, *, now=None):
    prefix = f"evidence/{incident_id}/"
    objects = s3.list_objects_v2(Bucket=bucket, Prefix=prefix).get("Contents", [])
    files = []
    for item in objects:
        if item["Key"] == f"{prefix}manifest.json":
            continue
        body = s3.get_object(Bucket=bucket, Key=item["Key"])["Body"].read()
        files.append(
            {
                "file_name": item["Key"].rsplit("/", 1)[-1],
                "sha256": hashlib.sha256(body).hexdigest(),
                "size_bytes": len(body),
                "s3_key": item["Key"],
            }
        )
    files.sort(key=lambda value: value["s3_key"])
    overall = hashlib.sha256("".join(value["sha256"] for value in files).encode()).hexdigest()
    manifest = {
        "incident_id": incident_id,
        "manifest_version": "1.0",
        "generated_at": (now or datetime.now(UTC)).isoformat(),
        "files": files,
        "overall_sha256": overall,
        "total_files": len(files),
        "total_size_bytes": sum(value["size_bytes"] for value in files),
    }
    put_json(s3, bucket, f"{prefix}manifest.json", manifest, kms_key_id)
    return manifest
