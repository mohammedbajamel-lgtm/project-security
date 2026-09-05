variable "env_code" { type = string }
variable "security_account_id" { type = string }
variable "remediation_role_arn" { type = string }
variable "approval_function_arn" { type = string }
variable "security_bus_name" { type = string }
variable "security_bus_arn" { type = string }
variable "dlq_arn" { type = string }
variable "incidents_table_name" { type = string }
variable "tags" {
  type    = map(string)
  default = {}
}

data "archive_file" "framework" {
  type        = "zip"
  source_dir  = "${path.root}/../lambda"
  output_path = "${path.root}/.terraform/cloudsec-${var.env_code}-remediation-framework.zip"
  excludes    = ["**/__pycache__/**", "**/*.pyc"]
}

resource "aws_lambda_function" "framework" {
  function_name    = "cloudsec-${var.env_code}-remediation-framework"
  role             = var.remediation_role_arn
  runtime          = "python3.11"
  handler          = "remediation.framework_handler.lambda_handler"
  filename         = data.archive_file.framework.output_path
  source_code_hash = data.archive_file.framework.output_base64sha256
  timeout          = 30
  memory_size      = 512
  logging_config {
    log_format = "JSON"
    log_group  = "cloudsec/${var.env_code}/remediation-framework"
  }
  environment {
    variables = {
      ENV_CODE             = var.env_code
      INCIDENTS_TABLE_NAME = var.incidents_table_name
      SECURITY_BUS_NAME    = var.security_bus_name
    }
  }
  tags = merge(var.tags, { Component = "remediation-framework" })
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["states.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.security_account_id]
    }
  }
}
resource "aws_iam_role" "state_machine" {
  name               = "cloudsec-${var.env_code}-remediation-state-machine-role"
  assume_role_policy = data.aws_iam_policy_document.assume.json
  tags               = var.tags
}
data "aws_iam_policy_document" "invoke" {
  statement {
    actions   = ["lambda:InvokeFunction"]
    resources = [aws_lambda_function.framework.arn, var.approval_function_arn]
  }
}
resource "aws_iam_role_policy" "invoke" {
  name   = "invoke-remediation-framework"
  role   = aws_iam_role.state_machine.id
  policy = data.aws_iam_policy_document.invoke.json
}

resource "aws_sfn_state_machine" "remediation" {
  name     = "cloudsec-${var.env_code}-remediation-executor"
  role_arn = aws_iam_role.state_machine.arn
  definition = jsonencode({
    Comment        = "Safety-gated remediation with human approval callback"
    StartAt        = "PrepareDecision"
    TimeoutSeconds = 86400
    States = {
      PrepareDecision = {
        Type       = "Pass"
        Parameters = { "decision.$" = "$" }
        Next       = "RouteByLevel"
      }
      RouteByLevel = {
        Type = "Choice"
        Choices = [
          { Variable = "$.decision.level", NumericEquals = 1, Next = "ValidateDecision" },
          { Variable = "$.decision.level", NumericEquals = 2, Next = "WaitForApproval" },
        ]
        Default = "UnsupportedDecision"
      }
      UnsupportedDecision = {
        Type       = "Pass"
        Result     = { Error = "UnsafeDecision", Cause = "Only Level 1 or approved Level 2 may execute" }
        ResultPath = "$.error"
        Next       = "OnFailure"
      }
      WaitForApproval = {
        Type           = "Task"
        Resource       = "arn:aws:states:::lambda:invoke.waitForTaskToken"
        TimeoutSeconds = 86400
        Parameters = {
          FunctionName = var.approval_function_arn
          Payload = {
            mode           = "register"
            "decision.$"   = "$.decision"
            "task_token.$" = "$$.Task.Token"
          }
        }
        ResultPath = "$.decision"
        Catch      = [{ ErrorEquals = ["States.ALL"], ResultPath = "$.error", Next = "OnFailure" }]
        Next       = "ValidateDecision"
      }
      ValidateDecision = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.framework.arn
          Payload      = { mode = "validate", "decision.$" = "$.decision" }
        }
        OutputPath = "$.Payload"
        Retry      = [{ ErrorEquals = ["Lambda.ServiceException", "Lambda.TooManyRequestsException"], IntervalSeconds = 2, MaxAttempts = 2, BackoffRate = 2 }]
        Catch      = [{ ErrorEquals = ["States.ALL"], ResultPath = "$.error", Next = "OnFailure" }]
        Next       = "ExecutePlaybook"
      }
      ExecutePlaybook = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.framework.arn
          Payload      = { mode = "execute", "decision.$" = "$.decision" }
        }
        OutputPath = "$.Payload"
        Retry      = [{ ErrorEquals = ["Lambda.ServiceException", "Lambda.TooManyRequestsException"], IntervalSeconds = 2, MaxAttempts = 2, BackoffRate = 2 }]
        Catch      = [{ ErrorEquals = ["States.ALL"], ResultPath = "$.error", Next = "OnFailure" }]
        Next       = "OnSuccess"
      }
      OnSuccess = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.framework.arn
          Payload      = { mode = "success", "decision.$" = "$.decision", "result.$" = "$.result" }
        }
        OutputPath = "$.Payload"
        End        = true
      }
      OnFailure = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = aws_lambda_function.framework.arn
          Payload      = { mode = "failure", "decision.$" = "$.decision", "error.$" = "$.error" }
        }
        OutputPath = "$.Payload"
        Next       = "WorkflowFailed"
      }
      WorkflowFailed = {
        Type  = "Fail"
        Error = "RemediationFailed"
        Cause = "Remediation was rejected, unsafe, or failed during execution"
      }
    }
  })
  tags = var.tags
}

data "aws_iam_policy_document" "eventbridge_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "eventbridge_start" {
  name               = "cloudsec-${var.env_code}-eventbridge-start-remediation"
  assume_role_policy = data.aws_iam_policy_document.eventbridge_assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy" "eventbridge_start" {
  name = "start-remediation-state-machine"
  role = aws_iam_role.eventbridge_start.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "states:StartExecution"
      Resource = aws_sfn_state_machine.remediation.arn
    }]
  })
}

resource "aws_cloudwatch_event_rule" "approved_decisions" {
  name           = "cloudsec-${var.env_code}-approved-remediation"
  event_bus_name = var.security_bus_name
  event_pattern = jsonencode({
    "detail-type" = ["RemediationApproved", "RemediationApprovalRequired"]
  })
  tags = var.tags
}

resource "aws_cloudwatch_event_target" "approved_decisions" {
  rule           = aws_cloudwatch_event_rule.approved_decisions.name
  event_bus_name = var.security_bus_name
  arn            = aws_sfn_state_machine.remediation.arn
  role_arn       = aws_iam_role.eventbridge_start.arn
  input_path     = "$.detail"
  dead_letter_config {
    arn = var.dlq_arn
  }
}

resource "aws_cloudwatch_event_rule" "rejected_decisions" {
  name           = "cloudsec-${var.env_code}-rejected-remediation"
  event_bus_name = var.security_bus_name
  event_pattern = jsonencode({
    "detail-type" = ["RemediationRejected"]
  })
  tags = var.tags
}

resource "aws_cloudwatch_event_target" "rejected_decisions" {
  rule           = aws_cloudwatch_event_rule.rejected_decisions.name
  event_bus_name = var.security_bus_name
  arn            = aws_lambda_function.framework.arn
  input_transformer {
    input_paths    = { detail = "$.detail" }
    input_template = <<-EOT
      {"mode":"failure","decision":<detail>,"error":{"Error":"SafetyValidationFailed","Cause":"Safety validation rejected remediation"}}
    EOT
  }
}

resource "aws_lambda_permission" "rejected_decisions" {
  statement_id  = "AllowRejectedDecisionEscalation"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.framework.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.rejected_decisions.arn
}

output "state_machine_arn" { value = aws_sfn_state_machine.remediation.arn }
