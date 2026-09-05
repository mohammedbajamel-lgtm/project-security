resource "aws_config_configuration_aggregator" "this" {
  name = "cloudsec-${var.env_code}-config-aggregator"
  dynamic "organization_aggregation_source" {
    for_each = var.organization_mode ? [1] : []
    content {
      role_arn    = var.organization_role_arn
      all_regions = true
    }
  }
  dynamic "account_aggregation_source" {
    for_each = var.organization_mode ? [] : [1]
    content {
      account_ids = var.account_ids
      regions     = var.regions
    }
  }
  tags = merge(var.tags, { Component = "aws-config" })
}

output "aggregator_arn" { value = aws_config_configuration_aggregator.this.arn }
