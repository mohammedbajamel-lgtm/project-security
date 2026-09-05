variable "env_code" { type = string }
variable "account_id" { type = string }
variable "evidence_key_arn" { type = string }
variable "retention_days" { type = number }
variable "noncurrent_transition_days" { type = number }
variable "tags" { type = map(string) }
variable "source_dir" { type = string }
variable "reporting_role_arn" { type = string }
variable "incidents_table_name" { type = string }
variable "remediation_audit_table_name" { type = string }
variable "security_bus_name" { type = string }

data "archive_file" "evidence" {
  type        = "zip"
  source_dir  = var.source_dir
  output_path = "${path.root}/.terraform/cloudsec-${var.env_code}-evidence.zip"
  excludes    = ["**/__pycache__/**", "**/*.pyc"]
}

resource "aws_s3_bucket" "access_logs" {
  bucket        = "cloudsec-${var.env_code}-${var.account_id}-evidence-access-logs"
  force_destroy = false
  tags          = merge(var.tags, { Component = "evidence-access-logs" })
}
resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket                  = aws_s3_bucket.access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket" "evidence" {
  bucket              = "cloudsec-${var.env_code}-evidence-${var.account_id}"
  force_destroy       = false
  object_lock_enabled = true
  tags                = merge(var.tags, { Component = "forensic-evidence", DataSensitivity = "EVIDENCE" })
}
resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.evidence_key_arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}
resource "aws_s3_bucket_object_lock_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.retention_days
    }
  }
  depends_on = [aws_s3_bucket_versioning.evidence]
}
resource "aws_s3_bucket_logging" "evidence" {
  bucket        = aws_s3_bucket.evidence.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "evidence-access/"
}
resource "aws_s3_bucket_lifecycle_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    id     = "archive-noncurrent-evidence"
    status = "Enabled"
    filter {}
    noncurrent_version_transition {
      noncurrent_days = var.noncurrent_transition_days
      storage_class   = "GLACIER"
    }
  }
  depends_on = [aws_s3_bucket_versioning.evidence]
}

data "aws_iam_policy_document" "evidence" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.evidence.arn, "${aws_s3_bucket.evidence.arn}/*"]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
  statement {
    sid    = "DenyIncorrectEncryptionHeader"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.evidence.arn}/*"]
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
  }
}
resource "aws_s3_bucket_policy" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  policy = data.aws_iam_policy_document.evidence.json
}

resource "aws_cloudwatch_log_group" "evidence" {
  name              = "/aws/lambda/cloudsec-${var.env_code}-evidence-packager"
  retention_in_days = 30
  tags              = var.tags
}
resource "aws_lambda_function" "evidence" {
  function_name    = "cloudsec-${var.env_code}-evidence-packager"
  role             = var.reporting_role_arn
  runtime          = "python3.11"
  handler          = "evidence.main.lambda_handler"
  filename         = data.archive_file.evidence.output_path
  source_code_hash = data.archive_file.evidence.output_base64sha256
  timeout          = 120
  memory_size      = 512
  logging_config {
    log_format = "JSON"
    log_group  = "cloudsec/${var.env_code}/evidence-packager"
  }
  environment {
    variables = {
      EVIDENCE_BUCKET_NAME         = aws_s3_bucket.evidence.id
      EVIDENCE_KEY_ARN             = var.evidence_key_arn
      INCIDENTS_TABLE_NAME         = var.incidents_table_name
      REMEDIATION_AUDIT_TABLE_NAME = var.remediation_audit_table_name
    }
  }
  tags       = var.tags
  depends_on = [aws_cloudwatch_log_group.evidence]
}
resource "aws_cloudwatch_event_rule" "terminal_incident" {
  name           = "cloudsec-${var.env_code}-preserve-terminal-incident"
  event_bus_name = var.security_bus_name
  event_pattern = jsonencode({
    "detail-type" = ["IncidentResolved", "IncidentEscalated"]
  })
  tags = var.tags
}
resource "aws_cloudwatch_event_target" "evidence" {
  rule           = aws_cloudwatch_event_rule.terminal_incident.name
  event_bus_name = var.security_bus_name
  arn            = aws_lambda_function.evidence.arn
}
resource "aws_lambda_permission" "events" {
  statement_id  = "AllowTerminalIncidentEvidence"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.evidence.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.terminal_incident.arn
}

output "bucket_name" { value = aws_s3_bucket.evidence.id }
output "bucket_arn" { value = aws_s3_bucket.evidence.arn }
output "retention_days" { value = var.retention_days }
output "function_name" { value = aws_lambda_function.evidence.function_name }
