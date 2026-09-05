# CloudSec AI - Root Variables (main platform)
#
# These are the variables consumed by the root main.tf. Environment-specific
# tfvars files (dev/dev.tfvars, staging/..., prod/...) supply the values.

variable "environment" {
  description = "Deployment environment"
  type        = string
  validation {
    condition     = contains(["dev", "staging", "prod", "lab", "demo"], var.environment)
    error_message = "Environment must be dev, staging, prod, lab, or demo."
  }
}

variable "enable_lab_environment" {
  description = "Provision isolated Phase 18 controls. Valid only for lab or demo environments."
  type        = bool
  default     = false
  validation {
    condition     = !var.enable_lab_environment || contains(["lab", "demo"], var.environment)
    error_message = "Lab resources may only be enabled when environment is lab or demo."
  }
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "cost_center" {
  type    = string
  default = "security"
}

variable "project_name" {
  type    = string
  default = "cloudsec-ai"
}

variable "created_by" {
  type    = string
  default = "cloudsec-platform"
}

# ---- Account IDs ----
variable "security_account_id" {
  description = "AWS account ID for the Security Account"
  type        = string
}

variable "workload_account_id" {
  description = "AWS account ID for the Workload Account (may equal security for single-account dev)"
  type        = string
}

# ---- Role ARNs to assume (for provider auth) ----
variable "security_account_role_arn" {
  type        = string
  description = "Role ARN to assume for the Security Account provider alias"
}

variable "workload_account_role_arn" {
  type        = string
  description = "Role ARN to assume for the Workload Account provider alias"
}

# ---- IAM principals allowed to assume CloudSec AI roles ----
variable "allowed_terraform_principal_arn" {
  description = "IAM user/role ARN allowed to assume the terraform-deploy role"
  type        = string
}

variable "allowed_security_admin_principal_arn" {
  description = "IAM user/role ARN allowed to assume the security-admin break-glass role"
  type        = string
}

variable "cost_alert_email" {
  description = "Optional email address subscribed to dev cost alerts"
  type        = string
  default     = null
  nullable    = true
}

variable "enable_guardduty_ingestion" {
  type    = bool
  default = true
}

variable "enable_securityhub_ingestion" {
  type    = bool
  default = true
}

variable "enable_config_ingestion" {
  type    = bool
  default = true
}

variable "telemetry_reserved_concurrency" {
  description = "Reserved concurrency per telemetry Lambda; -1 uses account unreserved concurrency"
  type        = number
  default     = -1
  validation {
    condition     = var.telemetry_reserved_concurrency == -1 || var.telemetry_reserved_concurrency >= 1
    error_message = "Use -1 for unreserved concurrency or a value of at least 1."
  }
}

variable "baseline_reserved_concurrency" {
  description = "Reserved concurrency for baselines; -1 supports low-quota dev accounts"
  type        = number
  default     = -1
  validation {
    condition     = var.baseline_reserved_concurrency == -1 || var.baseline_reserved_concurrency == 2
    error_message = "Use -1 for unreserved concurrency or 2 when quota permits."
  }
}

variable "enable_organization_cloudtrail" {
  type    = bool
  default = false
}

variable "enable_cloudtrail_object_lock" {
  type    = bool
  default = false
}

variable "cloudtrail_object_lock_retention_days" {
  type    = number
  default = 30
  validation {
    condition     = var.cloudtrail_object_lock_retention_days >= 1
    error_message = "Object Lock retention must be at least one day."
  }
}

variable "enable_config_aggregator" {
  type    = bool
  default = false
}

variable "enable_organization_config_aggregation" {
  type    = bool
  default = false
}

variable "config_organization_role_arn" {
  type     = string
  default  = null
  nullable = true
}

variable "enable_security_lake" {
  type    = bool
  default = false
}

variable "security_lake_meta_store_manager_role_arn" {
  type     = string
  default  = null
  nullable = true
}

variable "telemetry_account_ids" {
  type    = list(string)
  default = []
}

variable "telemetry_regions" {
  type    = list(string)
  default = ["us-east-1"]
}
