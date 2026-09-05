# CloudSec AI - KMS Key Module
#
# Creates customer-managed KMS keys used across the platform:
#   * incident_key  - incident table, SNS incident topics
#   * evidence_key  - evidence preservation S3 bucket
#   * finding_key   - findings table, DLQ (SSE-KMS)
#   * ssm_key       - SSM parameters (config, secrets references)
#
# Each key:
#   - Enables automatic key rotation (annual).
#   - Sets deletion_window_in_days = 30 (safety margin before permanent delete).
#   - Applies the standard key policy scoped to the Terraform deploy role,
#     the security-account root, and a set of allowlisted IAM roles.
#   - Creates a key alias following the naming standard.

resource "aws_kms_key" "incident_key" {
  description              = "CloudSec AI - Encrypts incident data and incident SNS topics"
  enable_key_rotation      = true
  deletion_window_in_days  = 30
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  policy                   = data.aws_iam_policy_document.incident_key_policy.json
  tags = merge(var.tags, {
    Name            = "cloudsec-${var.env_code}-incident-key"
    Component       = "kms"
    DataSensitivity = "EVIDENCE"
  })
}

resource "aws_kms_alias" "incident_key" {
  name          = var.incident_key_alias
  target_key_id = aws_kms_key.incident_key.key_id
}

resource "aws_kms_key" "evidence_key" {
  description              = "CloudSec AI - Encrypts the evidence preservation S3 bucket"
  enable_key_rotation      = true
  deletion_window_in_days  = 30
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  policy                   = data.aws_iam_policy_document.evidence_key_policy.json
  tags = merge(var.tags, {
    Name            = "cloudsec-${var.env_code}-evidence-key"
    Component       = "kms"
    DataSensitivity = "EVIDENCE"
  })
}

resource "aws_kms_alias" "evidence_key" {
  name          = var.evidence_key_alias
  target_key_id = aws_kms_key.evidence_key.key_id
}

resource "aws_kms_key" "finding_key" {
  description              = "CloudSec AI - Encrypts findings table, DLQ, and ingestor queues"
  enable_key_rotation      = true
  deletion_window_in_days  = 30
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  policy                   = data.aws_iam_policy_document.finding_key_policy.json
  tags = merge(var.tags, {
    Name            = "cloudsec-${var.env_code}-finding-key"
    Component       = "kms"
    DataSensitivity = "FINDINGS"
  })
}

resource "aws_kms_alias" "finding_key" {
  name          = var.finding_key_alias
  target_key_id = aws_kms_key.finding_key.key_id
}

resource "aws_kms_key" "ssm_key" {
  description              = "CloudSec AI - Encrypts SSM parameters used by Lambda functions"
  enable_key_rotation      = true
  deletion_window_in_days  = 30
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  policy                   = data.aws_iam_policy_document.ssm_key_policy.json
  tags = merge(var.tags, {
    Name            = "cloudsec-${var.env_code}-ssm-key"
    Component       = "kms"
    DataSensitivity = "CONFIG"
  })
}

resource "aws_kms_alias" "ssm_key" {
  name          = var.ssm_key_alias
  target_key_id = aws_kms_key.ssm_key.key_id
}
