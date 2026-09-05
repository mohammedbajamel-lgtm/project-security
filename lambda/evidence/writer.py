"""Shared KMS-encrypted JSON evidence writer."""

import json


def put_json(s3, bucket, key, value, kms_key_id):
    body = json.dumps(value, sort_keys=True, default=str, separators=(",", ":")).encode()
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=body,
        ContentType="application/json",
        ServerSideEncryption="aws:kms",
        SSEKMSKeyId=kms_key_id,
    )
    return {"s3_key": key, "size_bytes": len(body)}
