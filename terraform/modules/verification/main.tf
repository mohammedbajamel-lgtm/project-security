variable "env_code" { type = string }
variable "source_dir" { type = string }
variable "role_arn" { type = string }
variable "incidents_table_name" { type = string }
variable "security_bus_name" { type = string }
variable "security_bus_arn" { type = string }
variable "escalations_topic_arn" { type = string }
variable "reserved_concurrency" {
  type    = number
  default = -1
}
variable "tags" { type = map(string) }

data "archive_file" "this" {
  type        = "zip"
  source_dir  = var.source_dir
  output_path = "${path.root}/.terraform/cloudsec-${var.env_code}-verification.zip"
  excludes    = ["**/__pycache__/**", "**/*.pyc"]
}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/aws/lambda/cloudsec-${var.env_code}-verification-engine"
  retention_in_days = 30
  tags              = var.tags
}

resource "aws_lambda_function" "this" {
  function_name    = "cloudsec-${var.env_code}-verification-engine"
  role             = var.role_arn
  runtime          = "python3.11"
  handler          = "verification.main.lambda_handler"
  filename         = data.archive_file.this.output_path
  source_code_hash = data.archive_file.this.output_base64sha256
  timeout          = 60
  memory_size      = 512
  logging_config {
    log_format = "JSON"
    log_group  = "cloudsec/${var.env_code}/verification-engine"
  }
  reserved_concurrent_executions = var.reserved_concurrency
  environment {
    variables = {
      ENV_CODE              = var.env_code
      INCIDENTS_TABLE_NAME  = var.incidents_table_name
      SECURITY_BUS_NAME     = var.security_bus_name
      ESCALATIONS_TOPIC_ARN = var.escalations_topic_arn
    }
  }
  tags       = var.tags
  depends_on = [aws_cloudwatch_log_group.this]
}

resource "aws_cloudwatch_event_rule" "this" {
  name           = "cloudsec-${var.env_code}-remediation-executed"
  event_bus_name = var.security_bus_name
  event_pattern = jsonencode({
    "detail-type" = ["RemediationExecuted"]
  })
  tags = var.tags
}
resource "aws_cloudwatch_event_target" "this" {
  rule           = aws_cloudwatch_event_rule.this.name
  event_bus_name = var.security_bus_name
  arn            = aws_lambda_function.this.arn
}
resource "aws_lambda_permission" "events" {
  statement_id  = "AllowSecurityBusVerification"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.this.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.this.arn
}

output "function_name" { value = aws_lambda_function.this.function_name }
