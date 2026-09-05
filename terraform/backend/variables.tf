# CloudSec AI - Backend Bootstrap Variables
#
# Only variables genuinely consumed by the backend bootstrap are declared
# here. Account ID and region are sourced from the authenticated AWS
# identity (data.aws_caller_identity.current, data.aws_region.current)
# rather than trusted from tfvars input.

variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod."
  }
}

variable "region" {
  description = "AWS region for backend resources"
  type        = string
  default     = "us-east-1"
}

variable "cost_center" {
  description = "Cost center tag value"
  type        = string
  default     = "security"
}

variable "terraform_deploy_role_arn" {
  description = "ARN of the Terraform deployment role granted access to the remote state and lock objects"
  type        = string

  validation {
    condition     = can(regex("^arn:aws:iam::[0-9]{12}:role/.+$", var.terraform_deploy_role_arn))
    error_message = "terraform_deploy_role_arn must be an IAM role ARN; IAM user ARNs are not allowed."
  }
}
