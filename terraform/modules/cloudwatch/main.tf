variable "env_code" { type = string }
variable "region" { type = string }
variable "account_id" { type = string }
variable "errors_topic_arn" { type = string }
variable "state_machine_arn" { type = string }
variable "incidents_table_name" { type = string }
variable "findings_table_name" { type = string }
variable "dlq_name" { type = string }
variable "log_retention_days" { type = number }
variable "lambda_functions" { type = map(number) }
variable "tags" { type = map(string) }

resource "aws_cloudwatch_log_group" "lambda" {
  for_each          = var.lambda_functions
  name              = "cloudsec/${var.env_code}/${trimprefix(each.key, "cloudsec-${var.env_code}-")}"
  retention_in_days = var.log_retention_days
  tags              = var.tags
}

locals {
  lambda_error_alarms = {
    for name, timeout in var.lambda_functions : name => {
      alarm_name = "cloudsec-${var.env_code}-lambda-${name}-errors"
      metric     = "Errors"
      statistic  = "Sum"
      threshold  = 0
      priority   = "P2"
    }
  }
  lambda_throttle_alarms = {
    for name, timeout in var.lambda_functions : name => {
      alarm_name = "cloudsec-${var.env_code}-lambda-${name}-throttles"
      metric     = "Throttles"
      statistic  = "Sum"
      threshold  = 0
      priority   = "P2"
    }
  }
  lambda_duration_alarms = {
    for name, timeout in var.lambda_functions : name => {
      alarm_name = "cloudsec-${var.env_code}-lambda-${name}-duration"
      metric     = "Duration"
      statistic  = "Average"
      threshold  = timeout * 900
      priority   = "P3"
    }
  }
  lambda_alarms = merge(local.lambda_error_alarms, {
    for name, alarm in local.lambda_throttle_alarms : "${name}-throttle" => alarm
    }, {
    for name, alarm in local.lambda_duration_alarms : "${name}-duration" => alarm
  })
}

resource "aws_cloudwatch_metric_alarm" "lambda" {
  for_each            = local.lambda_alarms
  alarm_name          = each.value.alarm_name
  alarm_description   = "${each.value.priority}: ${each.value.metric} threshold for ${split("-", each.key)[0]}"
  namespace           = "AWS/Lambda"
  metric_name         = each.value.metric
  statistic           = each.value.statistic
  period              = 300
  evaluation_periods  = 1
  comparison_operator = "GreaterThanThreshold"
  threshold           = each.value.threshold
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.errors_topic_arn]
  ok_actions          = [var.errors_topic_arn]
  dimensions = {
    FunctionName = replace(replace(each.key, "-throttle", ""), "-duration", "")
  }
  tags = var.tags
}

resource "aws_cloudwatch_composite_alarm" "lambda_health" {
  alarm_name        = "cloudsec-${var.env_code}-lambda-health"
  alarm_description = "P2/P3 aggregate Lambda health"
  alarm_rule        = join(" OR ", [for alarm in aws_cloudwatch_metric_alarm.lambda : "ALARM(\"${alarm.alarm_name}\")"])
  alarm_actions     = [var.errors_topic_arn]
  ok_actions        = [var.errors_topic_arn]
  tags              = var.tags
}

locals {
  state_machine_alarms = {
    failed   = "ExecutionsFailed"
    timedout = "ExecutionsTimedOut"
  }
}
resource "aws_cloudwatch_metric_alarm" "state_machine" {
  for_each            = local.state_machine_alarms
  alarm_name          = "cloudsec-${var.env_code}-stepfunctions-${each.key}"
  alarm_description   = "P2: remediation state machine ${each.key}"
  namespace           = "AWS/States"
  metric_name         = each.value
  statistic           = "Sum"
  period              = 600
  evaluation_periods  = 1
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.errors_topic_arn]
  dimensions          = { StateMachineArn = var.state_machine_arn }
  tags                = var.tags
}

locals {
  custom_alarms = {
    schema        = { namespace = "CloudSec/AI", metric = "SchemaValidationError", threshold = 3, period = 3600, priority = "P2" }
    bedrock       = { namespace = "CloudSec/AI", metric = "BedrockFailure", threshold = 5, period = 3600, priority = "P2" }
    hallucination = { namespace = "CloudSec/AI", metric = "HallucinationDetected", threshold = 0, period = 3600, priority = "P3" }
    verification  = { namespace = "CloudSec/Operations", metric = "VerificationFailed", threshold = 0, period = 900, priority = "P2" }
    escalation    = { namespace = "CloudSec/Operations", metric = "IncidentEscalated", threshold = 0, period = 900, priority = "P1" }
  }
}
resource "aws_cloudwatch_metric_alarm" "custom" {
  for_each            = local.custom_alarms
  alarm_name          = "cloudsec-${var.env_code}-${each.key}"
  alarm_description   = "${each.value.priority}: ${each.value.metric}"
  namespace           = each.value.namespace
  metric_name         = each.value.metric
  statistic           = "Sum"
  period              = each.value.period
  evaluation_periods  = 1
  comparison_operator = "GreaterThanThreshold"
  threshold           = each.value.threshold
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.errors_topic_arn]
  tags                = var.tags
}

locals {
  lambda_widgets = [for name, timeout in var.lambda_functions : {
    type = "metric", width = 12, height = 6,
    properties = {
      title = "Lambda: ${name}", region = var.region, view = "timeSeries", period = 300,
      metrics = [
        ["AWS/Lambda", "Invocations", "FunctionName", name],
        [".", "Errors", ".", "."], [".", "Duration", ".", "."], [".", "Throttles", ".", "."]
      ]
    }
  }]
  overview_widgets = concat([
    { type = "text", width = 24, height = 1, properties = { markdown = "# Telemetry Ingestion" } },
    { type = "metric", width = 12, height = 6, properties = { title = "DLQ depth and ingestion health", region = var.region, metrics = [["AWS/SQS", "ApproximateNumberOfMessagesVisible", "QueueName", var.dlq_name], ["CloudSec/Telemetry", "IngestionLag"]] } },
    { type = "text", width = 24, height = 1, properties = { markdown = "# Incidents" } },
    { type = "metric", width = 12, height = 6, properties = { title = "Incident outcomes", region = var.region, metrics = [["CloudSec/Operations", "IncidentResolved"], [".", "IncidentEscalated"]] } },
    { type = "text", width = 24, height = 1, properties = { markdown = "# AI Investigation" } },
    { type = "metric", width = 12, height = 6, properties = { title = "Bedrock outcomes", region = var.region, metrics = [["CloudSec/AI", "BedrockInvocation"], [".", "BedrockSuccess"], [".", "BedrockFailure"], [".", "SchemaValidationError"]] } },
    { type = "text", width = 24, height = 1, properties = { markdown = "# Remediation" } },
    { type = "metric", width = 12, height = 6, properties = { title = "Remediation and verification", region = var.region, metrics = [["CloudSec/Operations", "RemediationExecuted"], [".", "RemediationFailed"], [".", "VerificationPassed"], [".", "VerificationFailed"]] } },
    { type = "text", width = 24, height = 1, properties = { markdown = "# System Health" } },
    { type = "metric", width = 12, height = 6, properties = { title = "Step Functions duration/failures", region = var.region, metrics = [["AWS/States", "ExecutionTime", "StateMachineArn", var.state_machine_arn], [".", "ExecutionsFailed", ".", "."], [".", "ExecutionsTimedOut", ".", "."]] } },
    { type = "metric", width = 12, height = 6, properties = { title = "DynamoDB throughput", region = var.region, metrics = [["AWS/DynamoDB", "ConsumedReadCapacityUnits", "TableName", var.incidents_table_name], [".", "ConsumedWriteCapacityUnits", ".", "."], ["AWS/DynamoDB", "ConsumedReadCapacityUnits", "TableName", var.findings_table_name], [".", "ConsumedWriteCapacityUnits", ".", "."]] } }
  ], local.lambda_widgets)
}

resource "aws_cloudwatch_dashboard" "overview" {
  dashboard_name = "cloudsec-${var.env_code}-overview"
  dashboard_body = jsonencode({ start = "-PT24H", widgets = local.overview_widgets })
}
resource "aws_cloudwatch_dashboard" "cost" {
  dashboard_name = "cloudsec-${var.env_code}-cost"
  dashboard_body = jsonencode({ start = "-PT24H", widgets = [
    { type = "text", width = 24, height = 2, properties = { markdown = "# Cost\nDaily service spend, Bedrock spend, and budget status are available in AWS Cost Explorer and Budgets." } },
    { type = "metric", width = 24, height = 6, properties = { title = "Estimated charges", region = "us-east-1", stat = "Maximum", period = 21600, metrics = [["AWS/Billing", "EstimatedCharges", "Currency", "USD"]] } }
  ] })
}
resource "aws_cloudwatch_dashboard" "security" {
  dashboard_name = "cloudsec-${var.env_code}-security"
  dashboard_body = jsonencode({ start = "-PT24H", widgets = [
    { type = "text", width = 24, height = 1, properties = { markdown = "# Active Alarms and Escalations" } },
    { type = "metric", width = 12, height = 6, properties = { title = "Escalated incidents", region = var.region, metrics = [["CloudSec/Operations", "IncidentEscalated"]] } },
    { type = "metric", width = 12, height = 6, properties = { title = "High-severity findings", region = var.region, metrics = [["CloudSec/Telemetry", "FindingIngested", "Severity", "HIGH"]] } },
    { type = "metric", width = 12, height = 6, properties = { title = "Anomaly scores", region = var.region, metrics = [["CloudSec/Baselines", "AnomalyScore"]] } }
  ] })
}

output "dashboard_names" { value = [aws_cloudwatch_dashboard.overview.dashboard_name, aws_cloudwatch_dashboard.cost.dashboard_name, aws_cloudwatch_dashboard.security.dashboard_name] }
output "lambda_health_alarm_arn" { value = aws_cloudwatch_composite_alarm.lambda_health.arn }
output "lambda_log_groups" { value = { for name, group in aws_cloudwatch_log_group.lambda : name => group.name } }
