resource "aws_securitylake_data_lake" "this" {
  meta_store_manager_role_arn = var.meta_store_manager_role_arn
  dynamic "configuration" {
    for_each = toset(var.regions)
    content { region = configuration.value }
  }
  tags = merge(var.tags, { Component = "security-lake" })
}

resource "aws_securitylake_aws_log_source" "vpc_flow" {
  source {
    accounts       = var.account_ids
    regions        = var.regions
    source_name    = "VPC_FLOW"
    source_version = "2.0"
  }
  depends_on = [aws_securitylake_data_lake.this]
}

output "data_lake_arn" { value = aws_securitylake_data_lake.this.arn }
