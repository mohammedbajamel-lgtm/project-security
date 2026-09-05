# CloudSec AI - Common Locals
# Shared values used across all modules to keep naming, tagging, and
# environment-specific logic in one place.

locals {
  # Short environment code used in resource names (e.g., "dev", "stg", "prd")
  env_short = {
    dev     = "dev"
    staging = "stg"
    prod    = "prd"
  }

  # Fully qualified prefix for all resource names:
  # cloudsec-{env_short}-{component}-{optional-unique}
  prefix = "cloudsec-${local.env_short[var.environment]}"

  # Canonical tag set applied to every resource via default_tags and explicit
  # tags blocks. Any resource-specific tags must be merged with common_tags.
  common_tags = {
    Project                = var.project_name
    Environment            = var.environment
    ManagedBy              = "terraform"
    CostCenter             = var.cost_center
    CreatedBy              = var.created_by
    IncidentClassification = "security-incident"
  }

  # Security-account-scoped identifiers
  security_account_id = var.security_account_id
  workload_account_id = var.workload_account_id

  # Region (canonical string for resource policy documents that require it)
  region = var.region
}
