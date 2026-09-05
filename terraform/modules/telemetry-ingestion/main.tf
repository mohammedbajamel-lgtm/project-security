data "archive_file" "package" {
  type        = "zip"
  source_dir  = var.source_dir
  output_path = "${path.module}/telemetry-ingestion.zip"
  excludes    = ["__pycache__", "*.pyc"]
}

locals {
  routes = {
    guardduty = { enabled = var.enable_guardduty_ingestion, handler = "ingestion.guardduty_ingestor.lambda_handler", source = "aws.guardduty", detail_type = "GuardDuty Finding", detail = null }
    securityhub = {
      enabled = var.enable_securityhub_ingestion, handler = "ingestion.securityhub_ingestor.lambda_handler"
      source  = "aws.securityhub", detail_type = "Security Hub Findings - Imported"
      detail  = { findings = { Severity = { Label = ["MEDIUM", "HIGH", "CRITICAL"] } } }
    }
    config = { enabled = var.enable_config_ingestion, handler = "ingestion.config_ingestor.lambda_handler", source = "aws.config", detail_type = "Config Configuration Item Change", detail = null }
  }
  enabled_routes = { for key, value in local.routes : key => value if value.enabled }
}

resource "aws_lambda_function" "ingestor" {
  for_each         = local.enabled_routes
  function_name    = "cloudsec-${var.env_code}-${each.key}-ingestor"
  role             = var.ingestion_role_arn
  runtime          = "python3.11"
  handler          = each.value.handler
  filename         = data.archive_file.package.output_path
  source_code_hash = data.archive_file.package.output_base64sha256
  memory_size      = 512
  logging_config {
    log_format = "JSON"
    log_group  = "cloudsec/${var.env_code}/${each.key}-ingestor"
  }
  timeout                        = 30
  reserved_concurrent_executions = var.reserved_concurrency
  environment { variables = { FINDINGS_TABLE = var.findings_table_name, SECURITY_BUS_NAME = var.security_bus_name, DLQ_URL = var.dlq_url } }
  tags = merge(var.tags, { Component = "telemetry-ingestion", Source = each.key })
}

resource "aws_cloudwatch_event_rule" "source" {
  for_each = local.enabled_routes
  name     = "cloudsec-${var.env_code}-${each.key}-findings"
  event_pattern = jsonencode(merge(
    { source = [each.value.source], "detail-type" = [each.value.detail_type] },
    each.value.detail == null ? {} : { detail = each.value.detail }
  ))
  tags = merge(var.tags, { Component = "telemetry-ingestion", Source = each.key })
}

resource "aws_cloudwatch_event_target" "lambda" {
  for_each  = local.enabled_routes
  rule      = aws_cloudwatch_event_rule.source[each.key].name
  target_id = "cloudsec-${each.key}-ingestor"
  arn       = aws_lambda_function.ingestor[each.key].arn
  dead_letter_config { arn = var.dlq_arn }
  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 2
  }
}

resource "aws_lambda_permission" "eventbridge" {
  for_each      = local.enabled_routes
  statement_id  = "AllowEventBridge-${each.key}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ingestor[each.key].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.source[each.key].arn
}

output "function_names" { value = { for key, value in aws_lambda_function.ingestor : key => value.function_name } }
