# CloudSec AI - Common Environment Variables
# Sourced from the environment-specific tfvars (dev/dev.tfvars, staging/...,
# prod/...). All variables that are environment-specific live here.

variable "environment" {
  description = "Deployment environment: dev | staging | prod"
  type        = string
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod."
  }
}

variable "region" {
  description = "AWS region for CloudSec AI resources"
  type        = string
  default     = "us-east-1"
}

variable "cost_center" {
  description = "Cost center tag for AWS cost allocation"
  type        = string
  default     = "security"
}

variable "security_account_id" {
  description = "AWS account ID for the Security Account (overridden from data.aws_caller_identity when role assumed)"
  type        = string
}

variable "workload_account_id" {
  description = "AWS account ID for the Workload Account"
  type        = string
}

# ---- Role ARNs for assume-role (multi-account access) ----
# These MUST be IAM roles (ARN format arn:aws:iam::ACCOUNT:role/NAME).
# IAM users are explicitly rejected by a regex validation to enforce the
# SSO/role-based authentication model.
variable "security_account_role_arn" {
  description = "IAM role ARN to assume in the Security Account"
  type        = string
  validation {
    condition     = can(regex("^arn:aws:iam::[0-9]{12}:role/.+$", var.security_account_role_arn))
    error_message = "security_account_role_arn must be an IAM role ARN (arn:aws:iam::<account>:role/<name>). IAM users are not permitted."
  }
}

variable "workload_account_role_arn" {
  description = "IAM role ARN to assume in the Workload Account"
  type        = string
  validation {
    condition     = can(regex("^arn:aws:iam::[0-9]{12}:role/.+$", var.workload_account_role_arn))
    error_message = "workload_account_role_arn must be an IAM role ARN (arn:aws:iam::<account>:role/<name>). IAM users are not permitted."
  }
}

# ---- Optional: AWS Organization role (enable when org-level policy work
# is needed in a later phase) ----
# variable "aws_organization_role_arn" {
#   description = "IAM role ARN in the Management Account with organizations:* permissions"
#   type        = string
#   default     = ""
# }

# ---- Operational ----
variable "project_name" {
  description = "Project prefix for all resources (used in naming standards)"
  type        = string
  default     = "cloudsec-ai"
}

variable "created_by" {
  description = "Principal or team that created/owns this deployment"
  type        = string
  default     = "cloudsec-platform"
}

variable "enable_developer_defaults" {
  description = "When true (dev), applies relaxed limits: lower budgets, no prod-only guardrails"
  type        = bool
  default     = true
}
