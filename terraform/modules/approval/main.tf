variable "env_code" { type = string }
variable "account_id" { type = string }
variable "source_dir" { type = string }
variable "approval_table_arn" { type = string }
variable "approval_table_name" { type = string }
variable "security_bus_arn" { type = string }
variable "security_bus_name" { type = string }
variable "escalations_topic_arn" { type = string }
variable "incident_key_arn" { type = string }
variable "enable_lab_password_auth" {
  type    = bool
  default = false
}
variable "tags" { type = map(string) }

data "archive_file" "lambda" {
  type        = "zip"
  source_dir  = var.source_dir
  output_path = "${path.root}/.terraform/cloudsec-${var.env_code}-approval.zip"
  excludes    = ["**/__pycache__/**", "**/*.pyc"]
}

resource "aws_cloudwatch_log_group" "handler" {
  name              = "/aws/lambda/cloudsec-${var.env_code}-approval-handler"
  retention_in_days = 30
  tags              = var.tags
}
resource "aws_cloudwatch_log_group" "expiry" {
  name              = "/aws/lambda/cloudsec-${var.env_code}-approval-expiry"
  retention_in_days = 30
  tags              = var.tags
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda" {
  name               = "cloudsec-${var.env_code}-approval-role"
  assume_role_policy = data.aws_iam_policy_document.assume.json
  tags               = var.tags
}

data "aws_iam_policy_document" "lambda" {
  statement {
    sid = "ApprovalDecisionLifecycle"
    actions = [
      "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem",
      "dynamodb:Query", "dynamodb:Scan"
    ]
    resources = [var.approval_table_arn]
  }
  statement {
    sid       = "StepFunctionsCallback"
    actions   = ["states:SendTaskSuccess", "states:SendTaskFailure"]
    resources = ["*"]
    # Callback APIs do not support resource-level permissions.
  }
  statement {
    sid       = "PublishApprovalEvents"
    actions   = ["events:PutEvents"]
    resources = [var.security_bus_arn]
  }
  statement {
    sid       = "PublishEscalations"
    actions   = ["sns:Publish"]
    resources = [var.escalations_topic_arn]
  }
  statement {
    sid = "UseIncidentTableKey"
    actions = [
      "kms:Decrypt",
      "kms:Encrypt",
      "kms:GenerateDataKey",
      "kms:GenerateDataKeyWithoutPlaintext",
      "kms:DescribeKey",
    ]
    resources = [var.incident_key_arn]
  }
  statement {
    sid     = "WriteLogs"
    actions = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = [
      "arn:aws:logs:*:${var.account_id}:log-group:/aws/lambda/cloudsec-${var.env_code}-approval-*:*",
      "arn:aws:logs:*:${var.account_id}:log-group:cloudsec/${var.env_code}/approval-*:*",
    ]
  }
}

resource "aws_iam_role_policy" "lambda" {
  name   = "cloudsec-${var.env_code}-approval-permissions"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda.json
}

resource "aws_lambda_function" "handler" {
  function_name    = "cloudsec-${var.env_code}-approval-handler"
  role             = aws_iam_role.lambda.arn
  runtime          = "python3.11"
  handler          = "approval.approval_handler.lambda_handler"
  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256
  timeout          = 30
  memory_size      = 512
  logging_config {
    log_format = "JSON"
    log_group  = "cloudsec/${var.env_code}/approval-handler"
  }
  environment { variables = { APPROVAL_TABLE_NAME = var.approval_table_name } }
  tags       = var.tags
  depends_on = [aws_cloudwatch_log_group.handler]
}

resource "aws_lambda_function" "expiry" {
  function_name    = "cloudsec-${var.env_code}-approval-expiry"
  role             = aws_iam_role.lambda.arn
  runtime          = "python3.11"
  handler          = "approval.expiry_handler.lambda_handler"
  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256
  timeout          = 60
  memory_size      = 256
  logging_config {
    log_format = "JSON"
    log_group  = "cloudsec/${var.env_code}/approval-expiry"
  }
  environment {
    variables = {
      APPROVAL_TABLE_NAME   = var.approval_table_name
      SECURITY_BUS_NAME     = var.security_bus_name
      ESCALATIONS_TOPIC_ARN = var.escalations_topic_arn
    }
  }
  tags       = var.tags
  depends_on = [aws_cloudwatch_log_group.expiry]
}

resource "aws_cloudwatch_event_rule" "expiry" {
  name                = "cloudsec-${var.env_code}-approval-expiry-check"
  schedule_expression = "rate(5 minutes)"
  tags                = var.tags
}
resource "aws_cloudwatch_event_target" "expiry" {
  rule = aws_cloudwatch_event_rule.expiry.name
  arn  = aws_lambda_function.expiry.arn
}
resource "aws_lambda_permission" "expiry" {
  statement_id  = "AllowApprovalExpirySchedule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.expiry.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.expiry.arn
}

resource "aws_cognito_user_pool" "this" {
  name = "cloudsec-${var.env_code}-user-pool"
  password_policy {
    minimum_length    = 14
    require_lowercase = true
    require_numbers   = true
    require_symbols   = true
    require_uppercase = true
  }
  tags = var.tags
}
resource "aws_cognito_user_group" "approver" {
  name         = "cloudsec_approver"
  user_pool_id = aws_cognito_user_pool.this.id
}
resource "aws_cognito_user_group" "viewer" {
  name         = "cloudsec_viewer"
  user_pool_id = aws_cognito_user_pool.this.id
}
resource "aws_cognito_user_pool_client" "api" {
  name                          = "cloudsec-${var.env_code}-approval-client"
  user_pool_id                  = aws_cognito_user_pool.this.id
  generate_secret               = false
  prevent_user_existence_errors = "ENABLED"
  access_token_validity         = 60
  id_token_validity             = 60
  refresh_token_validity        = 1
  token_validity_units {
    access_token  = "minutes"
    id_token      = "minutes"
    refresh_token = "days"
  }
  explicit_auth_flows = concat(
    ["ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    var.enable_lab_password_auth ? ["ALLOW_ADMIN_USER_PASSWORD_AUTH"] : []
  )
}

resource "aws_api_gateway_rest_api" "this" {
  name = "cloudsec-${var.env_code}-approval-api"
  endpoint_configuration { types = ["REGIONAL"] }
  tags = var.tags
}
resource "aws_api_gateway_authorizer" "cognito" {
  name          = "cloudsec-${var.env_code}-cognito"
  rest_api_id   = aws_api_gateway_rest_api.this.id
  type          = "COGNITO_USER_POOLS"
  provider_arns = [aws_cognito_user_pool.this.arn]
}

locals {
  routes = {
    pending = { path = "pending", method = "GET", parent = "decisions" }
    detail  = { path = "{decision_id}", method = "GET", parent = "decisions" }
    approve = { path = "approve", method = "POST", parent = "detail" }
    reject  = { path = "reject", method = "POST", parent = "detail" }
  }
}
resource "aws_api_gateway_resource" "decisions" {
  rest_api_id = aws_api_gateway_rest_api.this.id
  parent_id   = aws_api_gateway_rest_api.this.root_resource_id
  path_part   = "decisions"
}
resource "aws_api_gateway_resource" "detail" {
  rest_api_id = aws_api_gateway_rest_api.this.id
  parent_id   = aws_api_gateway_resource.decisions.id
  path_part   = "{decision_id}"
}
resource "aws_api_gateway_resource" "pending" {
  rest_api_id = aws_api_gateway_rest_api.this.id
  parent_id   = aws_api_gateway_resource.decisions.id
  path_part   = "pending"
}
resource "aws_api_gateway_resource" "approve" {
  rest_api_id = aws_api_gateway_rest_api.this.id
  parent_id   = aws_api_gateway_resource.detail.id
  path_part   = "approve"
}
resource "aws_api_gateway_resource" "reject" {
  rest_api_id = aws_api_gateway_rest_api.this.id
  parent_id   = aws_api_gateway_resource.detail.id
  path_part   = "reject"
}

locals {
  api_routes = {
    pending = { resource_id = aws_api_gateway_resource.pending.id, method = "GET" }
    detail  = { resource_id = aws_api_gateway_resource.detail.id, method = "GET" }
    approve = { resource_id = aws_api_gateway_resource.approve.id, method = "POST" }
    reject  = { resource_id = aws_api_gateway_resource.reject.id, method = "POST" }
  }
}
resource "aws_api_gateway_method" "route" {
  for_each      = local.api_routes
  rest_api_id   = aws_api_gateway_rest_api.this.id
  resource_id   = each.value.resource_id
  http_method   = each.value.method
  authorization = "COGNITO_USER_POOLS"
  authorizer_id = aws_api_gateway_authorizer.cognito.id
}
resource "aws_api_gateway_integration" "route" {
  for_each                = local.api_routes
  rest_api_id             = aws_api_gateway_rest_api.this.id
  resource_id             = each.value.resource_id
  http_method             = aws_api_gateway_method.route[each.key].http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.handler.invoke_arn
}
resource "aws_api_gateway_deployment" "this" {
  rest_api_id = aws_api_gateway_rest_api.this.id
  triggers    = { redeployment = sha1(jsonencode(local.api_routes)) }
  depends_on  = [aws_api_gateway_integration.route]
  lifecycle { create_before_destroy = true }
}
resource "aws_api_gateway_stage" "this" {
  deployment_id = aws_api_gateway_deployment.this.id
  rest_api_id   = aws_api_gateway_rest_api.this.id
  stage_name    = var.env_code
  tags          = var.tags
}
resource "aws_lambda_permission" "api" {
  statement_id  = "AllowApprovalApi"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.handler.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.this.execution_arn}/*/*"
}

output "api_url" { value = aws_api_gateway_stage.this.invoke_url }
output "user_pool_id" { value = aws_cognito_user_pool.this.id }
output "user_pool_client_id" { value = aws_cognito_user_pool_client.api.id }
output "handler_function_arn" { value = aws_lambda_function.handler.arn }
