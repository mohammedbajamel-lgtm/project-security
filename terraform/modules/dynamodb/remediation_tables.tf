resource "aws_dynamodb_table" "idempotency" {
  name         = var.idempotency_table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "idempotency_key"
  range_key    = "action"
  attribute {
    name = "idempotency_key"
    type = "S"
  }
  attribute {
    name = "action"
    type = "S"
  }
  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }
  server_side_encryption {
    enabled     = true
    kms_key_arn = var.incident_key_arn
  }
  point_in_time_recovery { enabled = true }
  deletion_protection_enabled = !var.disable_deletion_protection
  tags                        = merge(var.tags, { Component = "remediation-idempotency" })
}

resource "aws_dynamodb_table" "remediation_audit" {
  name         = var.remediation_audit_table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "execution_id"
  range_key    = "event_time"
  attribute {
    name = "execution_id"
    type = "S"
  }
  attribute {
    name = "event_time"
    type = "S"
  }
  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }
  server_side_encryption {
    enabled     = true
    kms_key_arn = var.incident_key_arn
  }
  point_in_time_recovery { enabled = true }
  deletion_protection_enabled = !var.disable_deletion_protection
  tags                        = merge(var.tags, { Component = "remediation-audit" })
}

output "idempotency_table_arn" { value = aws_dynamodb_table.idempotency.arn }
output "remediation_audit_table_arn" { value = aws_dynamodb_table.remediation_audit.arn }
output "idempotency_table_name" { value = aws_dynamodb_table.idempotency.name }
output "remediation_audit_table_name" { value = aws_dynamodb_table.remediation_audit.name }
