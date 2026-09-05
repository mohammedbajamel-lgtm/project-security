"""CloudSec operational custom metrics."""

import boto3


def emit_metric(name, *, value=1, dimensions=None, client=None):
    metric = {"MetricName": name, "Value": value, "Unit": "Count"}
    if dimensions:
        metric["Dimensions"] = [
            {"Name": key, "Value": str(item)} for key, item in sorted(dimensions.items())
        ]
    (client or boto3.client("cloudwatch")).put_metric_data(
        Namespace="CloudSec/Operations", MetricData=[metric]
    )
