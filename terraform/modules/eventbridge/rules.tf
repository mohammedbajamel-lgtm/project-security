# CloudSec AI - Internal Event Routing (T02-08)

locals {
  lambda_routes = {
    finding-ingested = {
      detail_type   = "FindingIngested"
      function_name = var.correlation_function_name
      function_arn  = aws_lambda_function.correlation.arn
    }
    incident-created = {
      detail_type   = "IncidentCreated"
      function_name = var.investigation_function_name
      function_arn  = aws_lambda_function.investigation.arn
    }
    investigation-completed = {
      detail_type   = "InvestigationCompleted"
      function_name = var.safety_validation_function_name
      function_arn  = aws_lambda_function.safety_validation.arn
    }
  }
}

data "archive_file" "correlation" {
  type        = "zip"
  source_dir  = "${path.root}/../lambda"
  output_path = "${path.root}/.terraform/${var.correlation_function_name}.zip"
  excludes    = ["**/__pycache__/**", "**/*.pyc"]
}

data "archive_file" "investigation" {
  type        = "zip"
  source_dir  = "${path.root}/../lambda"
  output_path = "${path.root}/.terraform/${var.investigation_function_name}.zip"
  excludes    = ["**/__pycache__/**", "**/*.pyc"]
}

data "archive_file" "safety_validation" {
  type        = "zip"
  source_dir  = "${path.root}/../lambda"
  output_path = "${path.root}/.terraform/${var.safety_validation_function_name}.zip"
  excludes    = ["**/__pycache__/**", "**/*.pyc"]
}

resource "aws_lambda_function" "correlation" {
  function_name    = var.correlation_function_name
  role             = var.correlation_role_arn
  runtime          = "python3.11"
  handler          = "correlation.main.lambda_handler"
  filename         = data.archive_file.correlation.output_path
  source_code_hash = data.archive_file.correlation.output_base64sha256
  timeout          = 30
  memory_size      = 512
  logging_config {
    log_format = "JSON"
    log_group  = "cloudsec/${var.env_code}/correlation"
  }
  environment {
    variables = {
      FINDINGS_TABLE_NAME  = var.findings_table_name
      INCIDENTS_TABLE_NAME = var.incidents_table_name
      SECURITY_BUS_NAME    = var.security_bus_name_for_lambda
      ENV_CODE             = var.env_code
    }
  }
  tags = merge(var.tags, { Component = "correlation" })
}

data "archive_file" "baseline" {
  type        = "zip"
  source_dir  = "${path.root}/../lambda"
  output_path = "${path.root}/.terraform/${var.baseline_function_name}.zip"
  excludes    = ["**/__pycache__/**", "**/*.pyc"]
}

resource "aws_lambda_function" "baseline" {
  function_name    = var.baseline_function_name
  role             = var.baseline_role_arn
  runtime          = "python3.11"
  handler          = "baselines.compute_baseline.lambda_handler"
  filename         = data.archive_file.baseline.output_path
  source_code_hash = data.archive_file.baseline.output_base64sha256
  timeout          = 300
  memory_size      = 512
  logging_config {
    log_format = "JSON"
    log_group  = "cloudsec/${var.env_code}/baseline-computation"
  }
  reserved_concurrent_executions = var.baseline_reserved_concurrency
  environment { variables = { BASELINES_TABLE_NAME = var.baselines_table_name } }
  tags = merge(var.tags, { Component = "behavior-baseline" })
}

resource "aws_cloudwatch_event_rule" "baseline_schedule" {
  name                = "cloudsec-${var.env_code}-baseline-computation"
  schedule_expression = "cron(0 3 * * ? *)"
  tags                = merge(var.tags, { Component = "behavior-baseline" })
}

resource "aws_cloudwatch_event_target" "baseline_schedule" {
  rule      = aws_cloudwatch_event_rule.baseline_schedule.name
  target_id = "baseline-computation"
  arn       = aws_lambda_function.baseline.arn
  input     = jsonencode({ mode = "daily_refresh" })
}

resource "aws_lambda_permission" "baseline_schedule" {
  statement_id  = "AllowBaselineSchedule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.baseline.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.baseline_schedule.arn
}

resource "aws_cloudwatch_metric_alarm" "baseline_failure" {
  alarm_name          = "cloudsec-${var.env_code}-baseline-computation-failure"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = aws_lambda_function.baseline.function_name }
  statistic           = "Sum"
  period              = 86400
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.error_topic_arn]
  tags                = merge(var.tags, { Component = "behavior-baseline" })
}

resource "aws_ssm_parameter" "correlation_windows" {
  for_each = { principal = 15, ip = 30, resource = 60 }
  name     = "/cloudsec/${var.env_code}/correlation/${each.key}_window_minutes"
  type     = "String"
  value    = tostring(each.value)
  tags     = merge(var.tags, { Component = "correlation" })
}

resource "aws_lambda_function" "investigation" {
  function_name    = var.investigation_function_name
  role             = var.investigation_role_arn
  runtime          = "python3.11"
  handler          = "investigation.main.lambda_handler"
  filename         = data.archive_file.investigation.output_path
  source_code_hash = data.archive_file.investigation.output_base64sha256
  timeout          = 90
  memory_size      = 1024
  logging_config {
    log_format = "JSON"
    log_group  = "cloudsec/${var.env_code}/investigation"
  }
  environment {
    variables = {
      ENV_CODE             = var.env_code
      INCIDENTS_TABLE_NAME = var.incidents_table_name
      SECURITY_BUS_NAME    = var.security_bus_name_for_lambda
    }
  }
  tags = merge(var.tags, { Component = "investigation" })
}

resource "aws_ssm_parameter" "ai_config" {
  for_each = {
    model_id        = "us.anthropic.claude-sonnet-4-6"
    max_tokens      = "4096"
    temperature     = "0"
    timeout_seconds = "60"
    retry_max       = "3"
  }
  name  = "/cloudsec/${var.env_code}/ai/${each.key}"
  type  = "String"
  value = each.value
  tags  = merge(var.tags, { Component = "ai-investigation" })
}

resource "aws_lambda_function" "safety_validation" {
  function_name    = var.safety_validation_function_name
  role             = var.safety_validation_role_arn
  runtime          = "python3.11"
  handler          = "safety.main.lambda_handler"
  filename         = data.archive_file.safety_validation.output_path
  source_code_hash = data.archive_file.safety_validation.output_base64sha256
  timeout          = 30
  memory_size      = 512
  logging_config {
    log_format = "JSON"
    log_group  = "cloudsec/${var.env_code}/safety-validation"
  }
  environment {
    variables = {
      ENV_CODE             = var.env_code
      SECURITY_BUS_NAME    = var.security_bus_name_for_lambda
      DECISIONS_TABLE_NAME = var.decisions_table_name
    }
  }
  tags = merge(var.tags, { Component = "safety-validation" })
}

resource "aws_cloudwatch_event_rule" "lambda_routes" {
  for_each = local.lambda_routes

  name           = "cloudsec-${var.env_code}-${each.key}"
  event_bus_name = aws_cloudwatch_event_bus.security_bus.name
  event_pattern  = jsonencode({ "detail-type" = [each.value.detail_type] })
  tags           = merge(var.tags, { Component = "eventbridge-routing" })
}

resource "aws_cloudwatch_event_target" "lambda_routes" {
  for_each = local.lambda_routes

  rule           = aws_cloudwatch_event_rule.lambda_routes[each.key].name
  event_bus_name = aws_cloudwatch_event_bus.security_bus.name
  target_id      = each.key
  arn            = each.value.function_arn

  dead_letter_config {
    arn = var.dlq_arn
  }
}

# Lambda targets use resource-based permissions. Supplying target role_arn for
# Lambda is not supported by EventBridge and would fail during PutTargets.
resource "aws_lambda_permission" "eventbridge" {
  for_each = local.lambda_routes

  statement_id  = "AllowCloudSecEventBridge-${each.key}"
  action        = "lambda:InvokeFunction"
  function_name = each.value.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.lambda_routes[each.key].arn
}

resource "aws_cloudwatch_event_rule" "investigation_failed" {
  name           = "cloudsec-${var.env_code}-investigation-failed"
  event_bus_name = aws_cloudwatch_event_bus.security_bus.name
  event_pattern  = jsonencode({ "detail-type" = ["InvestigationFailed"] })
  tags           = merge(var.tags, { Component = "eventbridge-routing" })
}

resource "aws_cloudwatch_event_target" "investigation_failed" {
  rule           = aws_cloudwatch_event_rule.investigation_failed.name
  event_bus_name = aws_cloudwatch_event_bus.security_bus.name
  target_id      = "investigation-failed-dlq"
  arn            = var.dlq_arn
}

output "routing_rule_arns" {
  description = "ARNs of the four internal routing rules"
  value = merge(
    { for name, rule in aws_cloudwatch_event_rule.lambda_routes : name => rule.arn },
    { investigation-failed = aws_cloudwatch_event_rule.investigation_failed.arn }
  )
}
