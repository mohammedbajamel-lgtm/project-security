variable "env_code" { type = string }
variable "source_dir" { type = string }
variable "role_arn" { type = string }
variable "evidence_bucket_name" { type = string }
variable "evidence_key_arn" { type = string }
variable "reports_topic_arn" { type = string }
variable "security_bus_name" { type = string }
variable "tags" { type = map(string) }

data "archive_file" "reporting" {
  type        = "zip"
  source_dir  = var.source_dir
  output_path = "${path.root}/.terraform/cloudsec-${var.env_code}-reporting.zip"
  excludes    = ["**/__pycache__/**", "**/*.pyc"]
}

resource "aws_cloudwatch_log_group" "reporting" {
  name              = "/aws/lambda/cloudsec-${var.env_code}-incident-reporting"
  retention_in_days = 30
  tags              = var.tags
}

resource "aws_lambda_function" "reporting" {
  function_name    = "cloudsec-${var.env_code}-incident-reporting"
  role             = var.role_arn
  runtime          = "python3.11"
  handler          = "reporting.main.lambda_handler"
  filename         = data.archive_file.reporting.output_path
  source_code_hash = data.archive_file.reporting.output_base64sha256
  timeout          = 30
  memory_size      = 512
  logging_config {
    log_format = "JSON"
    log_group  = "cloudsec/${var.env_code}/incident-reporting"
  }
  environment {
    variables = {
      EVIDENCE_BUCKET_NAME = var.evidence_bucket_name
      EVIDENCE_KEY_ARN     = var.evidence_key_arn
      REPORTS_TOPIC_ARN    = var.reports_topic_arn
    }
  }
  tags       = var.tags
  depends_on = [aws_cloudwatch_log_group.reporting]
}

locals {
  terminal_events = {
    resolved  = "IncidentResolved"
    escalated = "IncidentEscalated"
  }
}

resource "aws_cloudwatch_event_rule" "reporting" {
  for_each       = local.terminal_events
  name           = "cloudsec-${var.env_code}-report-${each.key}"
  event_bus_name = var.security_bus_name
  event_pattern = jsonencode({
    "detail-type" = [each.value]
  })
  tags = var.tags
}

resource "aws_cloudwatch_event_target" "reporting" {
  for_each       = local.terminal_events
  rule           = aws_cloudwatch_event_rule.reporting[each.key].name
  event_bus_name = var.security_bus_name
  arn            = aws_lambda_function.reporting.arn
}

resource "aws_lambda_permission" "events" {
  for_each      = local.terminal_events
  statement_id  = "AllowIncident${title(each.key)}Reporting"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.reporting.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.reporting[each.key].arn
}

output "function_name" { value = aws_lambda_function.reporting.function_name }
