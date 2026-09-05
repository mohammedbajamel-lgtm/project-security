"""Conservative sensitivity classification."""


def classify_resource(arn: str, overrides=None) -> dict:
    lower = arn.lower()
    overrides = overrides or {}
    if arn in overrides:
        return {"level": overrides[arn], "reason": "manual_override"}
    if any(x in lower for x in (":iam::", ":kms:", ":secretsmanager:")):
        return {"level": "critical", "reason": "identity_or_secret_resource"}
    if ":rds:" in lower:
        return {"level": "high", "reason": "database"}
    if ":s3:::" in lower and any(x in lower for x in ("data", "database", "backup")):
        return {"level": "high", "reason": "sensitive_bucket_name"}
    if any(x in lower for x in (":ec2:", ":lambda:")):
        return {"level": "medium", "reason": "compute_or_network_resource"}
    return {"level": "low", "reason": "default"}
