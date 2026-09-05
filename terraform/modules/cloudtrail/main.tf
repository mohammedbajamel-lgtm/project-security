resource "aws_s3_bucket" "logs" {
  bucket              = "cloudsec-${var.env_code}-cloudtrail-logs-${var.account_id}"
  force_destroy       = false
  object_lock_enabled = var.enable_object_lock
  tags                = merge(var.tags, { Component = "cloudtrail", DataSensitivity = "AUDIT" })
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_object_lock_configuration" "logs" {
  count  = var.enable_object_lock ? 1 : 0
  bucket = aws_s3_bucket.logs.id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.retention_days
    }
  }
}

data "aws_iam_policy_document" "logs" {
  statement {
    sid       = "AllowCloudTrailAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.logs.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
  statement {
    sid       = "AllowCloudTrailWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs.arn}/CloudTrail/AWSLogs/${var.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.logs.arn, "${aws_s3_bucket.logs.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "logs" {
  bucket = aws_s3_bucket.logs.id
  policy = data.aws_iam_policy_document.logs.json
}

resource "aws_cloudtrail" "organization" {
  name                          = "cloudsec-${var.env_code}-org-trail"
  s3_bucket_name                = aws_s3_bucket.logs.id
  s3_key_prefix                 = "CloudTrail"
  include_global_service_events = true
  is_multi_region_trail         = true
  is_organization_trail         = true
  enable_log_file_validation    = true
  enable_logging                = true
  event_selector {
    include_management_events = true
    read_write_type           = "All"
  }
  tags       = merge(var.tags, { Component = "cloudtrail" })
  depends_on = [aws_s3_bucket_policy.logs]
}

data "archive_file" "parser" {
  type        = "zip"
  source_dir  = var.source_dir
  output_path = "${path.module}/cloudtrail-parser.zip"
}

resource "aws_lambda_function" "parser" {
  function_name                  = "cloudsec-${var.env_code}-cloudtrail-parser"
  role                           = var.ingestion_role_arn
  runtime                        = "python3.11"
  handler                        = "cloudtrail_parser.lambda_handler"
  filename                       = data.archive_file.parser.output_path
  source_code_hash               = data.archive_file.parser.output_base64sha256
  memory_size                    = 1024
  timeout                        = 60
  reserved_concurrent_executions = 5
  environment {
    variables = {
      CLOUDTRAIL_BUCKET = aws_s3_bucket.logs.id
      FINDINGS_TABLE    = var.findings_table_name
      SECURITY_BUS_NAME = var.security_bus_name
      DLQ_URL           = var.dlq_url
    }
  }
  tags = merge(var.tags, { Component = "cloudtrail-parser" })
}

resource "aws_lambda_permission" "s3" {
  statement_id  = "AllowCloudTrailBucket"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.parser.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = aws_s3_bucket.logs.arn
}

resource "aws_s3_bucket_notification" "cloudtrail" {
  bucket = aws_s3_bucket.logs.id
  lambda_function {
    lambda_function_arn = aws_lambda_function.parser.arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = "CloudTrail/"
    filter_suffix       = ".json.gz"
  }
  depends_on = [aws_lambda_permission.s3]
}

output "bucket_name" { value = aws_s3_bucket.logs.id }
output "trail_arn" { value = aws_cloudtrail.organization.arn }
