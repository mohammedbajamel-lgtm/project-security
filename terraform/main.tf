# CloudSec AI — Root Terraform Module
#
# This file composes all sub-modules. Do not define resources here directly.
# All resources belong in terraform/modules/<service>/.
#
# Usage:
#   terraform init -backend-config=s3-backend-config.hcl
#   terraform plan  -var-file=environments/dev/dev.tfvars
#   terraform apply -var-file=environments/dev/dev.tfvars

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Providers are defined in terraform/environments/common/providers.tf

# Modules are composed per-environment in each environment's main.tf
# See terraform/environments/<env>/main.tf for the full module composition.
