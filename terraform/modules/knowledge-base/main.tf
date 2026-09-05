variable "env_code" { type = string }
variable "source_dir" { type = string }
variable "role_arn" { type = string }
variable "knowledge_base_table_name" { type = string }
variable "security_bus_name" { type = string }
variable "tags" { type = map(string) }

data "archive_file" "knowledge_base" {
  type        = "zip"
  source_dir  = var.source_dir
  output_path = "${path.root}/.terraform/cloudsec-${var.env_code}-knowledge-base.zip"
  excludes    = ["**/__pycache__/**", "**/*.pyc"]
}

resource "aws_cloudwatch_log_group" "knowledge_base" {
  name              = "/aws/lambda/cloudsec-${var.env_code}-knowledge-base-ingestor"
  retention_in_days = 30
  tags              = var.tags
}

resource "aws_lambda_function" "knowledge_base" {
  function_name    = "cloudsec-${var.env_code}-knowledge-base-ingestor"
  role             = var.role_arn
  runtime          = "python3.11"
  handler          = "knowledge_base.main.lambda_handler"
  filename         = data.archive_file.knowledge_base.output_path
  source_code_hash = data.archive_file.knowledge_base.output_base64sha256
  timeout          = 30
  memory_size      = 512
  logging_config {
    log_format = "JSON"
    log_group  = "cloudsec/${var.env_code}/knowledge-base-ingestor"
  }
  environment {
    variables = { KNOWLEDGE_BASE_TABLE_NAME = var.knowledge_base_table_name }
  }
  tags       = var.tags
  depends_on = [aws_cloudwatch_log_group.knowledge_base]
}

resource "aws_cloudwatch_event_rule" "resolved" {
  name           = "cloudsec-${var.env_code}-knowledge-base-resolved"
  event_bus_name = var.security_bus_name
  event_pattern  = jsonencode({ "detail-type" = ["IncidentResolved"] })
  tags           = var.tags
}
resource "aws_cloudwatch_event_target" "resolved" {
  rule           = aws_cloudwatch_event_rule.resolved.name
  event_bus_name = var.security_bus_name
  arn            = aws_lambda_function.knowledge_base.arn
}
resource "aws_lambda_permission" "events" {
  statement_id  = "AllowResolvedIncidentKnowledgeBase"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.knowledge_base.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.resolved.arn
}

output "function_name" { value = aws_lambda_function.knowledge_base.function_name }
