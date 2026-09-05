# CloudSec AI — Terraform Backend Bootstrap (Stage 1)
#
# This configuration CREATES the S3 bucket used as the remote backend for the
# main platform Terraform. It MUST be applied first using the LOCAL backend
# (no remote state), then the main platform configuration switches to use
# this bucket as its backend.
#
# TWO-STAGE BOOTSTRAP (resolves T01-02 ↔ T01-07 dependency cycle):
#   1. Stage 1 (this file, T01-02) - Apply with LOCAL backend. Creates
#      the S3 bucket with versioning, SSE-S3, block-public-access,
#      force_destroy=false, and a bucket policy containing ONLY security
#      Deny statements (insecure-transport, unencrypted-uploads). No
#      role-scoped Allow statements because the deploy role does not yet
#      exist (provisioned in T01-07).
#   2. Stage 2 (post-T01-07, SEPARATE reviewed plan) - Adds role-scoped
#      Allow statements + DenyStateObjectDeletion to the bucket policy.
#      No placeholder or nonexistent role ARN is ever written in Stage 1.
#   3. Configure main terraform/environments/<env>/backend.hcl to point
#      at the created bucket.
#   4. Apply main platform Terraform (remote backend with use_lockfile).
#
# Usage:
#   cd terraform/backend
#   terraform init
#   terraform plan -var-file=../environments/dev/dev.tfvars
#   terraform apply -var-file=../environments/dev/dev.tfvars
#
# Design notes:
#   - S3 STATE LOCKING uses `use_lockfile = true` in backend.hcl.
#     Terraform writes a transient `<state_key>.tflock` object
#     (e.g. cloudsec-dev/terraform.tfstate.tflock) to acquire and release
#     the lock. This is UNRELATED to `.terraform.lock.hcl`, which is
#     the local provider-version pin file written by `terraform init`
#     and MUST be committed to Git.
#   - force_destroy is FALSE in all environments. State buckets hold the
#     source-of-truth Terraform state; accidental deletion would be
#     catastrophic and is intentionally disallowed.
#   - Stage 1 bucket policy contains ONLY security Deny statements
#     (insecure-transport, unencrypted-uploads). Role-scoped Allow
#     statements + DenyStateObjectDeletion are added in Stage 2.
#   - The deploy role must have s3:GetObject/PutObject/DeleteObject on
#     `<state_key>.tflock` (to acquire and release the lock), but
#     s3:DeleteObject must NOT be granted on `terraform.tfstate`.
#   - No DynamoDB lock table. No backward-compatibility need.
#   - Administrative recovery path preserved via bucket ownership
#     (root account retains full access).

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
  }

  # Bootstrap uses LOCAL backend - no remote state yet (circular dependency).
  # Once the bucket exists, the main platform config uses it with
  # use_lockfile = true.
}

data "aws_caller_identity" "current" {}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project     = "cloudsec-ai"
      Environment = var.environment
      ManagedBy   = "terraform"
      CostCenter  = var.cost_center
    }
  }
}

# ─────────────────────────────────────────────────────────────────────────────
# S3 Bucket - Terraform state storage
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_s3_bucket" "terraform_state" {
  # Explicit bucket name with random suffix ensures global uniqueness and
  # stays well under the 63-character S3 bucket limit.
  # Format: cloudsec-{env}-{account}-state-{12-hex-chars}
  # Example: cloudsec-dev-000000000000-state-a1b2c3d4e5f6
  bucket = "cloudsec-${var.environment}-${data.aws_caller_identity.current.account_id}-state-${random_id.bucket_suffix.hex}"

  # NEVER auto-delete. State buckets are critical; destruction requires an
  # explicit manual action outside Terraform (and a minimum 7-day KMS key
  # deletion window if KMS is enabled later).
  force_destroy = false

  tags = {
    Name        = "cloudsec-${var.environment}-terraform-state"
    Project     = "cloudsec-ai"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Unique suffix for S3 bucket name (12-char hex).
# Prevents collisions across environments/accounts.
resource "random_id" "bucket_suffix" {
  byte_length = 6 # 12 hex characters
}

# ─── Versioning: preserve every state version for recoverability ────────────

resource "aws_s3_bucket_versioning" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  versioning_configuration {
    status = "Enabled"
  }
}

# ─── SSE-S3 encryption at rest (AES256) ─────────────────────────────────────
# T01-02 minimum. T01-06 will introduce customer-managed KMS keys; the
# bucket can be upgraded to SSE-KMS at that point.

resource "aws_s3_bucket_server_side_encryption_configuration" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# ─── Block ALL public access (defense-in-depth, redundant with policy) ──────

resource "aws_s3_bucket_public_access_block" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ─── Bucket policy: Stage 2 - guardrails + deployment-role access ─────
#
# TWO-STAGE BOOTSTRAP DESIGN (resolves T01-02 ↔ T01-07 dependency cycle):
#
#   Stage 1 (T01-02, this file) — creates the bucket with versioning,
#   SSE-S3, block-public-access, force_destroy=false, and ONE bucket
#   policy that contains ONLY security Deny statements. No Allow
#   statements are added in Stage 1 because the Terraform deployment
#   role (provisioned in T01-07) does not yet exist. The authenticated
#   bootstrap operator's own IAM identity permissions are used for the
#   initial `terraform apply` — the bucket-policy Deny statements are
#   guarded by conditions (insecure transport, unencrypted uploads,
#   state-object deletion) so they do not block legitimate operational
#   access by the bootstrap operator or the bucket owner (root account).
#
#   Stage 2 (post-T01-07) — once the Terraform deployment role is
#   created, a SEPARATE reviewed plan adds narrowly-scoped Allow
#   statements for that role only. The expected Stage-2 policy is
#   documented in README.md under "Stage 2 Bucket Policy Template".
#   No placeholder or nonexistent role ARN is ever written into a
#   bucket policy in Stage 1.
#
# The completed Stage 2 policy retains the two Stage 1 Deny statements:
#   1. Deny insecure (HTTP) transport on all s3:* actions.
#   2. Deny unencrypted PutObject (SSE-S3 required).
# It also grants the deployment role only the state and lock-file permissions
# required by the S3 backend. State deletion is denied for that role, while
# lock-file deletion remains allowed so Terraform can release its lock.

resource "aws_s3_bucket_policy" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.terraform_state.arn,
          "${aws_s3_bucket.terraform_state.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid       = "DenyUnencryptedUploads"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.terraform_state.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "AES256"
          }
        }
      },
      {
        Sid    = "DenyStateObjectDeletion"
        Effect = "Deny"
        Principal = {
          AWS = var.terraform_deploy_role_arn
        }
        Action   = "s3:DeleteObject"
        Resource = "${aws_s3_bucket.terraform_state.arn}/cloudsec-${var.environment}/terraform.tfstate"
      },
      {
        Sid    = "AllowListBucketForStateDiscovery"
        Effect = "Allow"
        Principal = {
          AWS = var.terraform_deploy_role_arn
        }
        Action   = "s3:ListBucket"
        Resource = aws_s3_bucket.terraform_state.arn
        Condition = {
          StringEquals = {
            "s3:prefix" = "cloudsec-${var.environment}/"
          }
        }
      },
      {
        Sid    = "AllowStateObjectReadWrite"
        Effect = "Allow"
        Principal = {
          AWS = var.terraform_deploy_role_arn
        }
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = "${aws_s3_bucket.terraform_state.arn}/cloudsec-${var.environment}/terraform.tfstate"
      },
      {
        Sid    = "AllowStateLockFileReadWrite"
        Effect = "Allow"
        Principal = {
          AWS = var.terraform_deploy_role_arn
        }
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = "${aws_s3_bucket.terraform_state.arn}/cloudsec-${var.environment}/terraform.tfstate.tflock"
      }
    ]
  })
}

# ─────────────────────────────────────────────────────────────────────────────
# Outputs - consumed by main platform backend.hcl
# ─────────────────────────────────────────────────────────────────────────────

output "state_bucket_name" {
  description = "S3 bucket name for Terraform state storage"
  value       = aws_s3_bucket.terraform_state.id
}

output "state_bucket_arn" {
  description = "ARN of the Terraform state S3 bucket"
  value       = aws_s3_bucket.terraform_state.arn
}

output "state_key" {
  description = "S3 object key for the Terraform state file"
  value       = "cloudsec-${var.environment}/terraform.tfstate"
}

output "state_lock_file_key" {
  description = "S3 object key for the Terraform state lock file. "
  value       = "cloudsec-${var.environment}/terraform.tfstate.tflock"
}

output "auth_account_id" {
  description = "AWS account ID resolved from authenticated identity"
  value       = data.aws_caller_identity.current.account_id
}

output "backend_config" {
  description = "Copy-paste backend block for the main platform Terraform. "
  value       = <<-EOT
    terraform {
      backend "s3" {
        bucket         = "${aws_s3_bucket.terraform_state.id}"
        key            = "cloudsec-${var.environment}/terraform.tfstate"
        region         = "${var.region}"
        encrypt        = true
        use_lockfile   = true
      }
    }
  EOT
}
