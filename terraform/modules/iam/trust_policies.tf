# CloudSec AI - IAM Trust Policies
#
# Every role's trust policy is scoped to the minimum required service
# principal. No wildcard principals.

# Standard Lambda assume-role policy (used by all Lambda roles).
data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = [local.lambda_service_principal]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.security_account_id]
    }
  }
}

# Remediation role assumed by both Lambda and Step Functions.
data "aws_iam_policy_document" "remediation_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = [local.lambda_service_principal]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.security_account_id]
    }
  }
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = [local.states_service_principal]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.security_account_id]
    }
  }
}

# Terraform deploy role - assumed by the CI/CD runner principal(s).
# The allowed principals are explicitly provided; no wildcard.
data "aws_iam_policy_document" "terraform_deploy_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = var.allowed_terraform_principals
    }
    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }
  }
}

# Security admin break-glass role - assumed by human operators.
data "aws_iam_policy_document" "security_admin_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = var.allowed_security_admin_principals
    }
    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }
    condition {
      test     = "StringLike"
      variable = "aws:PrincipalTag/Team"
      values   = ["security"]
    }
  }
}
