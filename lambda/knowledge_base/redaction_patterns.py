"""Fail-closed redaction patterns used before storage or Bedrock prompts."""

PATTERNS = (
    ("TABLE", r"arn:aws:dynamodb:[^\s,;]+:table/[^\s,;]+"),
    ("ARN", r"arn:aws(?:-[a-z]+)?:[^\s,;]+"),
    ("S3_URL", r"(?:s3://|https?://[^\s/]+\.s3(?:\.[^\s/]+)?\.amazonaws\.com/)[^\s]+"),
    ("EMAIL", r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"),
    ("KEY", r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    (
        "IP",
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b|(?<![\w:])(?:[A-F0-9]{1,4}:){1,7}:[A-F0-9]{0,4}(?![\w:])|(?<![\w:])(?:[A-F0-9]{1,4}:){1,7}[A-F0-9]{1,4}(?![\w:])",
    ),
    ("ACCOUNT", r"(?<!\d)\d{12}(?!\d)"),
    (
        "SECRET",
        r"(?i)\b(?:secret(?:_access)?_key|password|passwd|token|api_key)\b\s*[:=]\s*['\"]?[^\s,'\"}]+",
    ),
)
