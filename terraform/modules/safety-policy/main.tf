variable "env_code" { type = string }
variable "security_account_id" { type = string }
variable "policy_path" { type = string }
variable "tags" {
  type    = map(string)
  default = {}
}

locals { policy = file(var.policy_path) }

resource "aws_s3_bucket" "policy" {
  bucket        = "cloudsec-${var.env_code}-${var.security_account_id}-safety-policy"
  force_destroy = false
  tags          = merge(var.tags, { Component = "safety-validation" })
}
resource "aws_s3_bucket_versioning" "policy" {
  bucket = aws_s3_bucket.policy.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_public_access_block" "policy" {
  bucket                  = aws_s3_bucket.policy.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_server_side_encryption_configuration" "policy" {
  bucket = aws_s3_bucket.policy.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
resource "aws_s3_object" "approved_actions" {
  bucket       = aws_s3_bucket.policy.id
  key          = "approved-action-policy.json"
  content      = local.policy
  etag         = filemd5(var.policy_path)
  content_type = "application/json"
  depends_on   = [aws_s3_bucket_versioning.policy]
}
resource "aws_ssm_parameter" "approved_actions" {
  name  = "/cloudsec/${var.env_code}/safety/approved_action_policy"
  type  = "String"
  value = local.policy
  tags  = merge(var.tags, { Component = "safety-validation" })
}
