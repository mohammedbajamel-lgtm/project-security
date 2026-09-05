# CloudSec AI - Naming Standards
#
# Convention: cloudsec-{env_short}-{component}-{optional-suffix}
#   env_short:  dev | stg | prd
#   component:  short kebab-case name of the subsystem
#   suffix:     for resources that need uniqueness (e.g., random hex on
#               S3 buckets, KMS keys with unique aliases)
#
# All resource names are generated from locals here so a single rename
# propagates to every module. Modules receive names via variables; they do
# not construct their own.

locals {
  env_short = {
    dev     = "dev"
    staging = "stg"
    prod    = "prd"
  }

  env_code = local.env_short[var.environment]

  # Prefix used in every name: cloudsec-{env_code}-
  prefix = "cloudsec-${local.env_code}"

  # ---- Storage ----
  state_bucket_name    = "${local.prefix}-terraform-state"
  evidence_bucket_name = "${local.prefix}-evidence"
  config_bucket_name   = "${local.prefix}-config"
  logs_bucket_name     = "${local.prefix}-logs"

  # ---- DynamoDB ----
  incidents_table_name = "${local.prefix}-incidents"
  findings_table_name  = "${local.prefix}-findings"

  # ---- SQS ----
  dlq_name               = "${local.prefix}-dlq"
  correlation_queue_name = "${local.prefix}-correlation"
  ingestion_queue_name   = "${local.prefix}-ingestion"

  # ---- SNS ----
  incidents_topic_name   = "${local.prefix}-incidents"
  escalations_topic_name = "${local.prefix}-escalations"
  errors_topic_name      = "${local.prefix}-errors"
  cost_alerts_topic_name = "${local.prefix}-cost-alerts"

  # ---- EventBridge ----
  security_bus_name = "${local.prefix}-security-bus"

  # ---- KMS key aliases (alias name, not ARN) ----
  # Aliases use a path-style format for clarity: alias/cloudsec/{env}/{component}
  incident_key_alias = "alias/cloudsec/${local.env_code}/incident"
  evidence_key_alias = "alias/cloudsec/${local.env_code}/evidence"
  finding_key_alias  = "alias/cloudsec/${local.env_code}/finding"
  ssm_key_alias      = "alias/cloudsec/${local.env_code}/ssm"

  # ---- Lambda (function name) ----
  guardduty_ingestor_fn_name   = "${local.prefix}-guardduty-ingestor"
  securityhub_ingestor_fn_name = "${local.prefix}-securityhub-ingestor"
  cloudtrail_ingestor_fn_name  = "${local.prefix}-cloudtrail-ingestor"
  vpcflow_ingestor_fn_name     = "${local.prefix}-vpcflow-ingestor"
  config_ingestor_fn_name      = "${local.prefix}-config-ingestor"
  correlation_engine_fn_name   = "${local.prefix}-correlation"
  investigation_fn_name        = "${local.prefix}-investigation"
  safety_validation_fn_name    = "${local.prefix}-safety-validation"
  verification_fn_name         = "${local.prefix}-verification"
  reporting_fn_name            = "${local.prefix}-reporting"

  # ---- Step Functions ----
  investigation_state_machine_name = "${local.prefix}-investigation-sm"
  remediation_state_machine_name   = "${local.prefix}-remediation-sm"

  # ---- IAM role base names ----
  terraform_deploy_role_name  = "${local.prefix}-terraform-deploy"
  correlation_role_name       = "${local.prefix}-correlation-role"
  investigation_role_name     = "${local.prefix}-investigation-role"
  safety_validation_role_name = "${local.prefix}-safety-validation-role"
  remediation_role_name       = "${local.prefix}-remediation-role"
  verification_role_name      = "${local.prefix}-verification-role"
  reporting_role_name         = "${local.prefix}-reporting-role"
  ingestion_role_name         = "${local.prefix}-ingestion-role"
  recovery_role_name          = "${local.prefix}-recovery-role"
  security_admin_role_name    = "${local.prefix}-security-admin-role"

  # ---- Budget ----
  monthly_budget_name = "${local.prefix}-monthly-budget"
}
