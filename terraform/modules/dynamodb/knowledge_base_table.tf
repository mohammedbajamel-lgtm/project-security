resource "aws_dynamodb_table" "knowledge_base" {
  name         = var.knowledge_base_table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "incident_id"
  range_key    = "ingested_at"

  attribute {
    name = "incident_id"
    type = "S"
  }
  attribute {
    name = "ingested_at"
    type = "S"
  }
  attribute {
    name = "attack_stage"
    type = "S"
  }
  attribute {
    name = "mitre_technique"
    type = "S"
  }
  attribute {
    name = "remediation_action"
    type = "S"
  }

  global_secondary_index {
    name            = "attack_stage-index"
    hash_key        = "attack_stage"
    range_key       = "ingested_at"
    projection_type = "ALL"
  }
  global_secondary_index {
    name            = "mitre_technique-index"
    hash_key        = "mitre_technique"
    range_key       = "ingested_at"
    projection_type = "ALL"
  }
  global_secondary_index {
    name            = "remediation_action-index"
    hash_key        = "remediation_action"
    range_key       = "ingested_at"
    projection_type = "ALL"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.incident_key_arn
  }
  point_in_time_recovery { enabled = true }
  deletion_protection_enabled = !var.disable_deletion_protection
  tags                        = merge(var.tags, { Component = "knowledge-base", DataSensitivity = "REDACTED" })
}

output "knowledge_base_table_arn" { value = aws_dynamodb_table.knowledge_base.arn }
output "knowledge_base_table_name" { value = aws_dynamodb_table.knowledge_base.name }
