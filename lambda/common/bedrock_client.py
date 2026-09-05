"""Restricted Bedrock invocation boundary with bounded retries."""

from __future__ import annotations

import json
import time
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from common.bedrock_metrics import emit_bedrock_metric

RETRYABLE = {"ThrottlingException", "ServiceUnavailableException"}


def invoke_bedrock(
    prompt: str,
    model_id: str,
    max_tokens: int,
    temperature: float,
    retry_max: int = 3,
    *,
    client: Any = None,
    sleeper=time.sleep,
    metrics: Any = None,
) -> dict[str, Any]:
    runtime = client or boto3.client("bedrock-runtime", config=Config(read_timeout=45))
    cloudwatch = metrics or boto3.client("cloudwatch")
    emit_bedrock_metric("BedrockInvocation", client=cloudwatch)
    tokens, length_retry = max_tokens, False
    for attempt in range(retry_max + 1):
        try:
            response = runtime.invoke_model(
                modelId=model_id,
                contentType="application/json",
                accept="application/json",
                body=json.dumps(
                    {
                        "anthropic_version": "bedrock-2023-05-31",
                        "max_tokens": tokens,
                        "temperature": temperature,
                        "messages": [{"role": "user", "content": prompt}],
                    }
                ),
            )
            payload = json.loads(response["body"].read())
            if payload.get("stop_reason") == "max_tokens" and not length_retry:
                length_retry, tokens = True, max(256, tokens // 2)
                continue
            emit_bedrock_metric("BedrockSuccess", client=cloudwatch)
            return payload
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            if code not in RETRYABLE or attempt == retry_max:
                emit_bedrock_metric(
                    "BedrockFailure",
                    dimension_name="failure_reason",
                    dimension_value=code,
                    client=cloudwatch,
                )
                raise
            cloudwatch.put_metric_data(
                Namespace="CloudSec/AI",
                MetricData=[
                    {
                        "MetricName": "BedrockRetryCount",
                        "Value": 1,
                        "Unit": "Count",
                        "Dimensions": [{"Name": "retry_reason", "Value": code}],
                    }
                ],
            )
            sleeper(2**attempt)
    raise RuntimeError("Bedrock response exceeded length limit")
