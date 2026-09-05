# CloudSec AI - DynamoDB Findings Table (T02-02)
#
# Stores normalized security findings from all telemetry sources
# (GuardDuty, Security Hub, CloudTrail, AWS Config, VPC Flow Logs).
#
# Key schema
#   PK  finding_id (String)  - UUID of the normalized finding
#   SK  ingested_at(String) - ISO 8601 timestamp when the finding was ingested
#
# GSIs (used by Phase 4 correlation engine)
#   principal-index on principal_arn + ingested_at
#   source-ip-index on source_ip    + ingested_at
#   resource-index  on resource_arn + ingested_at
#   account-index   on source_account + ingested_at
#
# Security
#   SSE with customer-managed KMS key (finding key).
#   Point-in-time recovery enabled, 35-day retention window.
#   Findings may contain IPs/ARNs - all data encrypted at rest.

resource "aws_dynamodb_table" "findings" {
  name         = var.findings_table_name
  billing_mode = "PAY_PER_REQUEST"

  hash_key  = "finding_id"
  range_key = "ingested_at"

  attribute {
    name = "finding_id"
    type = "S"
  }

  attribute {
    name = "ingested_at"
    type = "S"
  }

  attribute {
    name = "principal_arn"
    type = "S"
  }

  attribute {
    name = "source_ip"
    type = "S"
  }

  attribute {
    name = "resource_arn"
    type = "S"
  }

  attribute {
    name = "source_account"
    type = "S"
  }

  # GSI: correlate findings by principal identity
  global_secondary_index {
    name            = "principal-index"
    hash_key        = "principal_arn"
    range_key       = "ingested_at"
    projection_type = "ALL"
  }

  # GSI: correlate findings by source IP
  global_secondary_index {
    name            = "source-ip-index"
    hash_key        = "source_ip"
    range_key       = "ingested_at"
    projection_type = "ALL"
  }

  # GSI: correlate findings by target resource
  global_secondary_index {
    name            = "resource-index"
    hash_key        = "resource_arn"
    range_key       = "ingested_at"
    projection_type = "ALL"
  }

  # GSI: filter findings by workload account
  global_secondary_index {
    name            = "account-index"
    hash_key        = "source_account"
    range_key       = "ingested_at"
    projection_type = "ALL"
  }

  # Customer-managed KMS encryption (T01-06 finding key).
  server_side_encryption {
    enabled     = true
    kms_key_arn = var.finding_key_arn
  }

  point_in_time_recovery {
    enabled = true
  }

  deletion_protection_enabled = !var.disable_deletion_protection

  tags = merge(var.tags, {
    Name            = "cloudsec-${var.env_code}-findings"
    Component       = "dynamodb"
    DataSensitivity = "FINDINGS"
  })
}

output "findings_table_arn" {
  value       = aws_dynamodb_table.findings.arn
  description = "ARN of the findings DynamoDB table"
}

output "findings_table_name" {
  value       = aws_dynamodb_table.findings.name
  description = "Name of the findings DynamoDB table"
}
