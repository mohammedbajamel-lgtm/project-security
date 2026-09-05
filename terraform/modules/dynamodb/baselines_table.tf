resource "aws_dynamodb_table" "baselines" {
  name         = var.baselines_table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "principal_arn"
  range_key    = "baseline_date"

  attribute {
    name = "principal_arn"
    type = "S"
  }
  attribute {
    name = "baseline_date"
    type = "S"
  }
  attribute {
    name = "source_account"
    type = "S"
  }

  global_secondary_index {
    name            = "account-index"
    hash_key        = "source_account"
    range_key       = "baseline_date"
    projection_type = "ALL"
  }
  ttl {
    enabled        = true
    attribute_name = "ttl"
  }
  server_side_encryption {
    enabled     = true
    kms_key_arn = var.finding_key_arn
  }
  point_in_time_recovery {
    enabled = true
  }
  deletion_protection_enabled = !var.disable_deletion_protection
  tags = merge(var.tags, { Name = var.baselines_table_name, Component = "behavior-baseline",
  DataSensitivity = "BEHAVIORAL" })
}

output "baselines_table_arn" {
  value = aws_dynamodb_table.baselines.arn
}
output "baselines_table_name" {
  value = aws_dynamodb_table.baselines.name
}
