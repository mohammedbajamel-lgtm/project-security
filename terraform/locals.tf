# CloudSec AI - Root Locals
# Re-export naming and tag locals from the shared environments/common module.
# (Kept here at root so main.tf can compose module calls cleanly.)

locals {
  env_short = {
    dev     = "dev"
    staging = "stg"
    prod    = "prd"
    lab     = "lab"
  }

  env_code = local.env_short[var.environment]

  prefix = "cloudsec-${local.env_code}"

  common_tags = {
    Project                = var.project_name
    Environment            = var.environment
    ManagedBy              = "terraform"
    CostCenter             = var.cost_center
    CreatedBy              = var.created_by
    IncidentClassification = "security-incident"
  }

  # ---- KMS aliases ----
  incident_key_alias = "alias/cloudsec/${local.env_code}/incident"
  evidence_key_alias = "alias/cloudsec/${local.env_code}/evidence"
  finding_key_alias  = "alias/cloudsec/${local.env_code}/finding"
  ssm_key_alias      = "alias/cloudsec/${local.env_code}/ssm"

  # ---- DynamoDB ----
  incidents_table_name          = "${local.prefix}-incidents"
  findings_table_name           = "${local.prefix}-findings"
  baselines_table_name          = "${local.prefix}-baselines"
  decisions_table_name          = "${local.prefix}-safety-decisions"
  idempotency_table_name        = "${local.prefix}-idempotency"
  remediation_audit_table_name  = "${local.prefix}-remediation-audit"
  approval_decisions_table_name = "${local.prefix}-approval-decisions"
  knowledge_base_table_name     = "${local.prefix}-knowledge-base"

  # ---- S3 ----
  state_bucket_name    = "${local.prefix}-terraform-state"
  evidence_bucket_name = "${local.prefix}-evidence-${var.security_account_id}"
  config_bucket_name   = "${local.prefix}-config"
  logs_bucket_name     = "${local.prefix}-logs"

  # ---- SQS ----
  dlq_name               = "${local.prefix}-dlq"
  correlation_queue_name = "${local.prefix}-correlation"
  ingestion_queue_name   = "${local.prefix}-ingestion"

  # ---- SNS ----
  incidents_topic_name   = "${local.prefix}-incidents"
  escalations_topic_name = "${local.prefix}-escalations"
  errors_topic_name      = "${local.prefix}-errors"
  reports_topic_name     = "${local.prefix}-reports"
  cost_alerts_topic_name = "${local.prefix}-cost-alerts"

  # ---- EventBridge ----
  security_bus_name = "${local.prefix}-security-bus"

  # ---- Phase 2 routing target Lambdas ----
  correlation_engine_fn_name = "${local.prefix}-correlation"
  investigation_fn_name      = "${local.prefix}-investigation"
  safety_validation_fn_name  = "${local.prefix}-safety-validation"

  # ---- IAM role names ----
  terraform_deploy_role_name  = "${local.prefix}-terraform-deploy"
  ingestion_role_name         = "${local.prefix}-ingestion-role"
  correlation_role_name       = "${local.prefix}-correlation-role"
  investigation_role_name     = "${local.prefix}-investigation-role"
  safety_validation_role_name = "${local.prefix}-safety-validation-role"
  remediation_role_name       = "${local.prefix}-remediation-role"
  verification_role_name      = "${local.prefix}-verification-role"
  reporting_role_name         = "${local.prefix}-reporting-role"
  recovery_role_name          = "${local.prefix}-recovery-role"
  security_admin_role_name    = "${local.prefix}-security-admin-role"

  # ---- Budget ----
  monthly_budget_name = "${local.prefix}-monthly-budget"

  # ---- Monthly budget limit (dev/staging/prod) ----
  monthly_budget_limits = {
    dev     = 50
    staging = 200
    prod    = 500
    lab     = 25
  }

  monthly_budget_limit = local.monthly_budget_limits[var.environment]
}
