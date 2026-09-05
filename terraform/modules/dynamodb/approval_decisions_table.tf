resource "aws_dynamodb_table" "approval_decisions" {
  name                        = var.approval_decisions_table_name
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "decision_id"
  range_key                   = "created_at"
  deletion_protection_enabled = !var.disable_deletion_protection

  attribute {
    name = "decision_id"
    type = "S"
  }
  attribute {
    name = "created_at"
    type = "S"
  }
  ttl {
    attribute_name = "expires_at_epoch"
    enabled        = true
  }
  server_side_encryption {
    enabled     = true
    kms_key_arn = var.incident_key_arn
  }
  point_in_time_recovery { enabled = true }
  tags = merge(var.tags, { Component = "approval-decisions" })
}

output "approval_decisions_table_name" { value = aws_dynamodb_table.approval_decisions.name }
output "approval_decisions_table_arn" { value = aws_dynamodb_table.approval_decisions.arn }
