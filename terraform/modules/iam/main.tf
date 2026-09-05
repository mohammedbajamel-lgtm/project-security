# CloudSec AI - IAM Foundation Module
#
# Creates the base IAM roles used by every CloudSec AI component. Each role:
#   - Has a trust policy restricted to specific AWS service principals.
#   - Attaches only the least-privilege IAM policy that the role needs.
#   - Carries mandatory tags.
#   - Uses no inline policies with broad permissions.
#
# Roles created:
#   1. TerraformDeploy - used by the CI/CD pipeline to deploy CloudSec AI.
#   2. Ingestion - shared role for telemetry ingestor Lambdas.
#   3. Correlation - correlation engine Lambda + Step Functions.
#   4. Investigation - Bedrock-assisted investigation Lambda.
#   5. SafetyValidation - deterministic safety-validation Lambda.
#   6. Remediation - remediation executor Lambda + Step Functions.
#   7. Verification - post-remediation verification Lambda.
#   8. Reporting - forensic report generation Lambda.
#   9. Recovery - DLQ recovery / break-glass role.
#   10. SecurityAdmin - break-glass human operator role.

locals {
  lambda_service_principal = "lambda.amazonaws.com"
  events_service_principal = "events.amazonaws.com"
  states_service_principal = "states.amazonaws.com"
  s3_service_principal     = "s3.amazonaws.com"
}

# =========================================================
# TerraformDeploy Role (used by CI/CD, assumed by the runner)
# =========================================================
resource "aws_iam_role" "terraform_deploy" {
  name                 = var.terraform_deploy_role_name
  assume_role_policy   = data.aws_iam_policy_document.terraform_deploy_assume.json
  max_session_duration = 43200
  tags = merge(var.tags, {
    Name = "cloudsec-${var.env_code}-terraform-deploy"
  })
}

# Permissions are intentionally not attached here. Grant the deployment role
# only the actions required by each reviewed deployment stage; never attach
# AWS managed AdministratorAccess to this role.
# The Phase-2 deployment inline policy (cloudsec-dev-phase2-deployment)
# is attached below using the data source in policies.tf.
resource "aws_iam_role_policy" "terraform_deploy_phase2" {
  # Name matches the live policy created during Phase-1 apply so Terraform
  # adopts the existing policy rather than creating a duplicate.
  name   = "cloudsec-${var.env_code}-phase2-deployment"
  role   = aws_iam_role.terraform_deploy.id
  policy = data.aws_iam_policy_document.terraform_deploy_policy.json
}

# =========================================================
# Ingestion Role (GuardDuty, Security Hub, CloudTrail, Config ingestors)
# =========================================================
resource "aws_iam_role" "ingestion" {
  name                 = var.ingestion_role_name
  assume_role_policy   = data.aws_iam_policy_document.lambda_assume.json
  max_session_duration = 3600
  tags = merge(var.tags, {
    Name = "cloudsec-${var.env_code}-ingestion-role"
  })
}

resource "aws_iam_role_policy" "ingestion" {
  name   = "cloudsec-ingestion-permissions"
  role   = aws_iam_role.ingestion.id
  policy = data.aws_iam_policy_document.ingestion_policy.json
}

# =========================================================
# Correlation Engine Role
# =========================================================
resource "aws_iam_role" "correlation" {
  name                 = var.correlation_role_name
  assume_role_policy   = data.aws_iam_policy_document.lambda_assume.json
  max_session_duration = 3600
  tags = merge(var.tags, {
    Name = "cloudsec-${var.env_code}-correlation-role"
  })
}

resource "aws_iam_role_policy" "correlation" {
  name   = "cloudsec-correlation-permissions"
  role   = aws_iam_role.correlation.id
  policy = data.aws_iam_policy_document.correlation_policy.json
}

# =========================================================
# Investigation Role
# =========================================================
resource "aws_iam_role" "investigation" {
  name                 = var.investigation_role_name
  assume_role_policy   = data.aws_iam_policy_document.lambda_assume.json
  max_session_duration = 3600
  tags = merge(var.tags, {
    Name = "cloudsec-${var.env_code}-investigation-role"
  })
}

resource "aws_iam_role_policy" "investigation" {
  name   = "cloudsec-investigation-permissions"
  role   = aws_iam_role.investigation.id
  policy = data.aws_iam_policy_document.investigation_policy.json
}

# =========================================================
# Safety Validation Role
# =========================================================
resource "aws_iam_role" "safety_validation" {
  name                 = var.safety_validation_role_name
  assume_role_policy   = data.aws_iam_policy_document.lambda_assume.json
  max_session_duration = 3600
  tags = merge(var.tags, {
    Name = "cloudsec-${var.env_code}-safety-validation-role"
  })
}

resource "aws_iam_role_policy" "safety_validation" {
  name   = "cloudsec-safety-validation-permissions"
  role   = aws_iam_role.safety_validation.id
  policy = data.aws_iam_policy_document.safety_validation_policy.json
}

# =========================================================
# Remediation Role (invokes AWS services to remediate)
# =========================================================
resource "aws_iam_role" "remediation" {
  name                 = var.remediation_role_name
  assume_role_policy   = data.aws_iam_policy_document.remediation_assume.json
  max_session_duration = 3600
  tags = merge(var.tags, {
    Name = "cloudsec-${var.env_code}-remediation-role"
  })
}

resource "aws_iam_role_policy" "remediation" {
  name   = "cloudsec-remediation-permissions"
  role   = aws_iam_role.remediation.id
  policy = data.aws_iam_policy_document.remediation_policy.json
}

# =========================================================
# Verification Role
# =========================================================
resource "aws_iam_role" "verification" {
  name                 = var.verification_role_name
  assume_role_policy   = data.aws_iam_policy_document.lambda_assume.json
  max_session_duration = 3600
  tags = merge(var.tags, {
    Name = "cloudsec-${var.env_code}-verification-role"
  })
}

resource "aws_iam_role_policy" "verification" {
  name   = "cloudsec-verification-permissions"
  role   = aws_iam_role.verification.id
  policy = data.aws_iam_policy_document.verification_policy.json
}

# =========================================================
# Reporting Role
# =========================================================
resource "aws_iam_role" "reporting" {
  name                 = var.reporting_role_name
  assume_role_policy   = data.aws_iam_policy_document.lambda_assume.json
  max_session_duration = 3600
  tags = merge(var.tags, {
    Name = "cloudsec-${var.env_code}-reporting-role"
  })
}

resource "aws_iam_role_policy" "reporting" {
  name   = "cloudsec-reporting-permissions"
  role   = aws_iam_role.reporting.id
  policy = data.aws_iam_policy_document.reporting_policy.json
}

# =========================================================
# Recovery Role (DLQ recovery, break-glass)
# =========================================================
resource "aws_iam_role" "recovery" {
  name                 = var.recovery_role_name
  assume_role_policy   = data.aws_iam_policy_document.lambda_assume.json
  max_session_duration = 3600
  tags = merge(var.tags, {
    Name = "cloudsec-${var.env_code}-recovery-role"
  })
}

resource "aws_iam_role_policy" "recovery" {
  name   = "cloudsec-recovery-permissions"
  role   = aws_iam_role.recovery.id
  policy = data.aws_iam_policy_document.recovery_policy.json
}

# =========================================================
# SecurityAdmin Role (break-glass human, no inline wildcard)
# =========================================================
resource "aws_iam_role" "security_admin" {
  name                 = var.security_admin_role_name
  assume_role_policy   = data.aws_iam_policy_document.security_admin_assume.json
  max_session_duration = 43200
  tags = merge(var.tags, {
    Name = "cloudsec-${var.env_code}-security-admin-role"
  })
}

resource "aws_iam_role_policy_attachment" "security_admin_support" {
  role       = aws_iam_role.security_admin.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}
