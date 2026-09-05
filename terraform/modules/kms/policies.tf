# CloudSec AI - KMS Key Policies
#
# Least-privilege policy pattern:
#   - Root account can manage the key (admin recovery path).
#   - Terraform deploy role can manage the key (terraform apply lifecycle).
#   - Explicitly allowlisted service roles can ENCRYPT/DECRYPT (usage only).
#   - No wildcard principal in the usage statements.
#
# Every key policy uses the same structure; the service roles differ per key.

# ---- Incident key: used by incident table, investigation, reporting ----
data "aws_iam_policy_document" "incident_key_policy" {
  statement {
    sid       = "EnableRootAccountManagement"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.security_account_id}:root"]
    }
  }

  statement {
    sid       = "EnableTerraformDeploy"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = [var.terraform_deploy_role_arn]
    }
  }

  statement {
    sid       = "AllowIncidentServiceRoles"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type = "AWS"
      identifiers = [
        var.correlation_role_arn,
        var.investigation_role_arn,
        var.safety_validation_role_arn,
        var.reporting_role_arn,
      ]
    }
  }
}

# ---- Evidence key: used by evidence bucket, verification, reporting ----
data "aws_iam_policy_document" "evidence_key_policy" {
  statement {
    sid       = "EnableRootAccountManagement"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.security_account_id}:root"]
    }
  }

  statement {
    sid       = "EnableTerraformDeploy"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = [var.terraform_deploy_role_arn]
    }
  }

  statement {
    sid       = "AllowEvidenceServiceRoles"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type = "AWS"
      identifiers = [
        var.verification_role_arn,
        var.reporting_role_arn,
      ]
    }
  }
}

# ---- Finding key: used by findings table, DLQ, ingestion queues ----
data "aws_iam_policy_document" "finding_key_policy" {
  statement {
    sid       = "EnableRootAccountManagement"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.security_account_id}:root"]
    }
  }

  statement {
    sid       = "EnableTerraformDeploy"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = [var.terraform_deploy_role_arn]
    }
  }

  statement {
    sid       = "AllowFindingsServiceRoles"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type = "AWS"
      identifiers = [
        var.ingestion_role_arn,
        var.correlation_role_arn,
        var.investigation_role_arn,
        var.recovery_role_arn,
      ]
    }
  }

  statement {
    sid = "AllowEventBridgeEncryptedDLQDelivery"
    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey",
    ]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

# ---- SSM key: used by Lambda functions via SSM ----
data "aws_iam_policy_document" "ssm_key_policy" {
  statement {
    sid       = "EnableRootAccountManagement"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.security_account_id}:root"]
    }
  }

  statement {
    sid       = "EnableTerraformDeploy"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = [var.terraform_deploy_role_arn]
    }
  }

  statement {
    sid       = "AllowAllServiceRoles"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type = "AWS"
      identifiers = [
        var.ingestion_role_arn,
        var.correlation_role_arn,
        var.investigation_role_arn,
        var.safety_validation_role_arn,
        var.remediation_role_arn,
        var.verification_role_arn,
        var.reporting_role_arn,
      ]
    }
  }

  # AWS Budgets must generate and decrypt data keys when publishing to the
  # encrypted cost-alert SNS topic that uses this key.
  statement {
    sid = "AllowBudgetsToPublishEncryptedCostAlerts"
    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey*",
    ]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["budgets.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.security_account_id]
    }
  }
}
