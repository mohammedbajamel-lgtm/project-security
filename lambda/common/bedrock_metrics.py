"""Bedrock outcome metrics without logging prompts or response content."""

import boto3


def emit_bedrock_metric(name, *, dimension_name=None, dimension_value=None, client=None):
    allowed = {
        "BedrockInvocation",
        "BedrockSuccess",
        "BedrockFailure",
        "SchemaValidationError",
        "CitationValidationError",
        "HallucinationDetected",
    }
    if name not in allowed:
        raise ValueError("unsupported Bedrock metric")
    metric = {"MetricName": name, "Value": 1, "Unit": "Count"}
    if dimension_name and dimension_value:
        metric["Dimensions"] = [{"Name": dimension_name, "Value": str(dimension_value)}]
    (client or boto3.client("cloudwatch")).put_metric_data(
        Namespace="CloudSec/AI", MetricData=[metric]
    )
