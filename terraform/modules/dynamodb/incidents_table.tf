# CloudSec AI - DynamoDB Incidents Table (T02-01)
#
# Primary table for incident records. Each row is a single incident status
# transition; the most recent row per incident_id is the current state.
#
# Key schema
#   PK  incident_id (String)  - UUID of the incident
#   SK  event_time   (String) - ISO 8601 timestamp of the state transition
#
# GSIs
#   findings-index  on finding_id + event_time  (lookup by linked finding)
#   status-index    on status     + event_time  (list by current status)
#
# Security
#   SSE with customer-managed KMS key (incident key).
#   Point-in-time recovery enabled, 35-day retention window.
#   TTL attribute ttl enables automatic expiry of stale history rows.

resource "aws_dynamodb_table" "incidents" {
  name         = var.incidents_table_name
  billing_mode = "PAY_PER_REQUEST"

  hash_key  = "incident_id"
  range_key = "event_time"

  attribute {
    name = "incident_id"
    type = "S"
  }

  attribute {
    name = "event_time"
    type = "S"
  }

  attribute {
    name = "finding_id"
    type = "S"
  }

  attribute {
    name = "status"
    type = "S"
  }

  global_secondary_index {
    name            = "findings-index"
    hash_key        = "finding_id"
    range_key       = "event_time"
    projection_type = "ALL"
  }

  # GSI: list all rows by current status (OPEN, INVESTIGATING, ...)
  global_secondary_index {
    name            = "status-index"
    hash_key        = "status"
    range_key       = "event_time"
    projection_type = "ALL"
  }

  # TTL enables automatic deletion of stale history rows.
  ttl {
    enabled        = true
    attribute_name = "ttl"
  }

  # Customer-managed KMS encryption (T01-06 incident key).
  server_side_encryption {
    enabled     = true
    kms_key_arn = var.incident_key_arn
  }

  # Point-in-time recovery: 35-day window for forensic restore.
  point_in_time_recovery {
    enabled = true
  }

  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"

  deletion_protection_enabled = !var.disable_deletion_protection

  tags = merge(var.tags, {
    Name            = "cloudsec-${var.env_code}-incidents"
    Component       = "dynamodb"
    DataSensitivity = "EVIDENCE"
  })
}

# Output a stable reference to the table ARN + stream ARN.
output "incidents_table_arn" {
  value       = aws_dynamodb_table.incidents.arn
  description = "ARN of the incidents DynamoDB table"
}

output "incidents_table_name" {
  value       = aws_dynamodb_table.incidents.name
  description = "Name of the incidents DynamoDB table"
}

output "incidents_table_stream_arn" {
  value       = aws_dynamodb_table.incidents.stream_arn
  description = "DynamoDB stream ARN (NEW_AND_OLD_IMAGES) for incidents table"
}
