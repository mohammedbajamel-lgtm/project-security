# CloudSec AI - Multi-account Terraform Provider Configuration
#
# Provider architecture follows the security-account-hub pattern:
#   * `aws.security`   -> Security Account (GuardDuty, Security Hub, CloudTrail,
#                          Security Bus, centralized logging)
#   * `aws.workload`   -> default Workload Account (Lambda, DynamoDB, SQS, SNS)
#   * `aws` (unaliased) -> alias of security account used as default
#
# Every alias uses STS AssumeRole via a role ARN supplied by the environment
# tfvars. Access keys are NEVER hardcoded; the Terraform running identity must
# be an IAM user or SSO role with permission to assume the target role.
#
# Session tags flow to every assumed-role session, enabling CloudTrail
# filtering and cost allocation by environment/managed-by.
#
# Usage:
#   cd terraform
#   terraform init -backend-config=environments/dev/backend.hcl
#   terraform plan -var-file=environments/dev/dev.tfvars
#   terraform apply -var-file=environments/dev/dev.tfvars

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}

# ---- Shared provider data sources ----
# Account ID and region are sourced from the authenticated identity (STS).
# This ensures the deployed resource tags and cross-account policies always
# reference the ACTUAL account, not a value trusted from tfvars.

data "aws_caller_identity" "current" {
  provider = aws.security
}

data "aws_region" "current" {
  provider = aws.security
}

# ---- Security Account provider ----
# Central hub for GuardDuty, Security Hub, CloudTrail, the custom EventBridge
# bus, S3 evidence buckets, and any cross-account aggregation.
provider "aws" {
  alias  = "security"
  region = var.region
  default_tags {
    tags = local.common_tags
  }

  assume_role {
    role_arn     = var.security_account_role_arn
    session_name = "cloudsec-${var.environment}-deploy"
    session_tags = {
      Environment = var.environment
      ManagedBy   = "terraform"
      Project     = "cloudsec-ai"
      CostCenter  = var.cost_center
    }
    tag_session         = true
    transitive_tag_keys = ["Environment", "ManagedBy", "Project", "CostCenter"]
  }
}

# ---- Workload Account provider ----
# Hosts the compute/data layer: Lambda functions, DynamoDB tables, SQS queues,
# SNS topics, Step Functions state machines.
provider "aws" {
  alias  = "workload"
  region = var.region
  default_tags {
    tags = local.common_tags
  }

  assume_role {
    role_arn     = var.workload_account_role_arn
    session_name = "cloudsec-${var.environment}-deploy"
    session_tags = {
      Environment = var.environment
      ManagedBy   = "terraform"
      Project     = "cloudsec-ai"
      CostCenter  = var.cost_center
    }
    tag_session         = true
    transitive_tag_keys = ["Environment", "ManagedBy", "Project", "CostCenter"]
  }
}

# ---- Default provider (alias of security) ----
# Used by root-level resources that belong to the Security Account by default
# (e.g., the bootstrap S3 backend, KMS keys, IAM roles). Resources that need
# the workload account MUST explicitly set provider = aws.workload.
provider "aws" {
  region = var.region
  default_tags {
    tags = local.common_tags
  }

  assume_role {
    role_arn     = var.security_account_role_arn
    session_name = "cloudsec-${var.environment}-deploy"
    session_tags = {
      Environment = var.environment
      ManagedBy   = "terraform"
      Project     = "cloudsec-ai"
      CostCenter  = var.cost_center
    }
    tag_session         = true
    transitive_tag_keys = ["Environment", "ManagedBy", "Project", "CostCenter"]
  }
}

# ---- AWS Organizations provider (optional, used when account hierarchy
# is needed for cross-account policy deployment) ----
# Provider disabled by default; enable only when Organization root is
# accessible. Un-comment when cross-account SCP or policy propagation is
# added in a later phase.
# provider "awsorganizations" {
#   alias            = "org"
#   assume_role {
#     role_arn   = var.aws_organization_role_arn
#     session_name = "cloudsec-${var.environment}-org"
#   }
# }
