resource "aws_dynamodb_table" "safety_decisions" {
  name         = var.decisions_table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "decision_id"
  attribute {
    name = "decision_id"
    type = "S"
  }
  ttl {
    attribute_name = "expires_at_epoch"
    enabled        = true
  }
  point_in_time_recovery { enabled = true }
  server_side_encryption {
    enabled     = true
    kms_key_arn = var.incident_key_arn
  }
  deletion_protection_enabled = !var.disable_deletion_protection
  tags                        = merge(var.tags, { Name = var.decisions_table_name, Component = "safety-validation" })
}
output "decisions_table_arn" { value = aws_dynamodb_table.safety_decisions.arn }
output "decisions_table_name" { value = aws_dynamodb_table.safety_decisions.name }
