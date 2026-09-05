# CloudSec AI - Root Terraform Composition
#
# Entry point for the main CloudSec AI platform. Wires together sub-modules
# and composes their outputs. The bootstrap (terraform/backend/) is applied
# separately and is NOT included here.
#
# Phase 1 modules wired here now:
#   * kms              - 4 customer-managed KMS keys (T01-06)
#   * iam              - 10 IAM roles + scoped policies (T01-07)
#   * cost_controls    - budget + SNS alerts (T01-08)
#
# Phase 2 modules (wired in T02-* tasks):
#   * dynamodb (incidents + findings tables, T02-01 + T02-02)
#   * eventbridge_bus  (custom security event bus, T02-03)
#   * sqs_dlq          (DLQ for failed event processing, T02-04)
#   * sns_notifications (incident/escalation/error topics, T02-07)
#   * eventbridge_rules (routing rules on the security bus, T02-08)
#
# Phase 2 modules are NOT wired yet — they will be added after Phase 2 is
# implemented locally and reviewed. Placeholder comments below.
#
# Known design decisions:
#   * KMS ↔ IAM mutual dependency resolved by passing module outputs within
#     a single apply. Terraform resolves intra-apply references.
#   * IAM policies reference pre-declared ARNs for Phase-2 resources
#     (DynamoDB, SQS, SNS). These resources don't exist yet in dev; the
#     policies will be in place when the resources are created in Phase 2.

# =====================================================================
# Terraform block (S3 backend)
# Backend is configured per-environment via -backend-config=<env>.hcl.
# Kept explicit here to avoid the "Missing backend configuration" warning
# when passing -backend-config without an inline block.
# =====================================================================
terraform {
  backend "s3" {
    # Filled in by -backend-config=environments/<env>/backend.hcl
  }
}

module "lab_isolation" {
  count  = var.enable_lab_environment ? 1 : 0
  source = "./modules/lab-isolation"

  account_id = var.security_account_id
  region     = var.region
  tags       = merge(local.common_tags, { Isolation = "strict" })
}

# =====================================================================
# PHASE 1 modules
# =====================================================================

module "kms" {
  source = "./modules/kms"

  env_code            = local.env_code
  security_account_id = var.security_account_id

  terraform_deploy_role_arn = module.iam.terraform_deploy_role_arn

  correlation_role_arn       = module.iam.correlation_role_arn
  investigation_role_arn     = module.iam.investigation_role_arn
  safety_validation_role_arn = module.iam.safety_validation_role_arn
  remediation_role_arn       = module.iam.remediation_role_arn
  verification_role_arn      = module.iam.verification_role_arn
  reporting_role_arn         = module.iam.reporting_role_arn
  ingestion_role_arn         = module.iam.ingestion_role_arn
  recovery_role_arn          = module.iam.recovery_role_arn

  incident_key_alias = local.incident_key_alias
  evidence_key_alias = local.evidence_key_alias
  finding_key_alias  = local.finding_key_alias
  ssm_key_alias      = local.ssm_key_alias

  tags = local.common_tags
}

module "iam" {
  source = "./modules/iam"

  env_code            = local.env_code
  security_account_id = var.security_account_id
  region              = var.region

  terraform_deploy_role_name  = local.terraform_deploy_role_name
  ingestion_role_name         = local.ingestion_role_name
  correlation_role_name       = local.correlation_role_name
  investigation_role_name     = local.investigation_role_name
  safety_validation_role_name = local.safety_validation_role_name
  remediation_role_name       = local.remediation_role_name
  verification_role_name      = local.verification_role_name
  reporting_role_name         = local.reporting_role_name
  recovery_role_name          = local.recovery_role_name
  security_admin_role_name    = local.security_admin_role_name

  allowed_terraform_principals      = [var.allowed_terraform_principal_arn]
  allowed_security_admin_principals = [var.allowed_security_admin_principal_arn]

  # Phase-2 resources that don't exist in Phase 1. Policies will already
  # be scoped to the correct ARNs when the resources are created in Phase 2.
  incidents_table_arn         = "arn:aws:dynamodb:${var.region}:${var.security_account_id}:table/${local.incidents_table_name}"
  findings_table_arn          = "arn:aws:dynamodb:${var.region}:${var.security_account_id}:table/${local.findings_table_name}"
  baselines_table_arn         = "arn:aws:dynamodb:${var.region}:${var.security_account_id}:table/${local.baselines_table_name}"
  decisions_table_arn         = "arn:aws:dynamodb:${var.region}:${var.security_account_id}:table/${local.decisions_table_name}"
  idempotency_table_arn       = "arn:aws:dynamodb:${var.region}:${var.security_account_id}:table/${local.idempotency_table_name}"
  remediation_audit_table_arn = "arn:aws:dynamodb:${var.region}:${var.security_account_id}:table/${local.remediation_audit_table_name}"
  knowledge_base_table_arn    = "arn:aws:dynamodb:${var.region}:${var.security_account_id}:table/${local.knowledge_base_table_name}"
  evidence_bucket_arn         = "arn:aws:s3:::${local.evidence_bucket_name}"
  cloudtrail_bucket_arn       = "arn:aws:s3:::cloudsec-${local.env_code}-cloudtrail-logs-${var.security_account_id}"
  security_bus_arn            = "arn:aws:events:${var.region}:${var.security_account_id}:event-bus/${local.security_bus_name}"
  dlq_arn                     = "arn:aws:sqs:${var.region}:${var.security_account_id}:${local.dlq_name}"
  incidents_topic_arn         = "arn:aws:sns:${var.region}:${var.security_account_id}:${local.incidents_topic_name}"
  escalations_topic_arn       = "arn:aws:sns:${var.region}:${var.security_account_id}:${local.escalations_topic_name}"
  reports_topic_arn           = "arn:aws:sns:${var.region}:${var.security_account_id}:${local.reports_topic_name}"

  incidents_key_arn = module.kms.incident_key_arn
  evidence_key_arn  = module.kms.evidence_key_arn
  finding_key_arn   = module.kms.finding_key_arn
  ssm_key_arn       = module.kms.ssm_key_arn

  # Exact active US inference profile and backing models; no model wildcard.
  bedrock_model_arns = [
    "arn:aws:bedrock:us-east-1:${var.security_account_id}:inference-profile/us.anthropic.claude-sonnet-4-6",
    "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-sonnet-4-6",
    "arn:aws:bedrock:us-east-2::foundation-model/anthropic.claude-sonnet-4-6",
    "arn:aws:bedrock:us-west-2::foundation-model/anthropic.claude-sonnet-4-6",
  ]

  tags = local.common_tags
}

module "cost_controls" {
  source = "./modules/cost-controls"

  env_code            = local.env_code
  security_account_id = var.security_account_id
  environment         = var.environment
  project_name        = var.project_name

  monthly_budget_name    = local.monthly_budget_name
  cost_alerts_topic_name = local.cost_alerts_topic_name
  monthly_budget_limit   = local.monthly_budget_limit
  alert_email            = var.cost_alert_email

  ssm_key_arn = module.kms.ssm_key_arn
  tags        = local.common_tags
}

module "safety_policy" {
  source              = "./modules/safety-policy"
  env_code            = local.env_code
  security_account_id = var.security_account_id
  policy_path         = "${path.root}/../docs/approved-action-policy.json"
  tags                = local.common_tags
}

module "stepfunctions" {
  source                = "./modules/stepfunctions"
  depends_on            = [module.observability]
  env_code              = local.env_code
  security_account_id   = var.security_account_id
  remediation_role_arn  = module.iam.remediation_role_arn
  approval_function_arn = module.approval.handler_function_arn
  security_bus_name     = module.eventbridge_bus.security_bus_name
  security_bus_arn      = module.eventbridge_bus.security_bus_arn
  dlq_arn               = module.sqs_dlq.dlq_arn
  incidents_table_name  = module.dynamodb.incidents_table_name
  tags                  = local.common_tags
}

module "approval" {
  source                   = "./modules/approval"
  depends_on               = [module.observability]
  env_code                 = local.env_code
  account_id               = var.security_account_id
  source_dir               = "${path.root}/../lambda"
  approval_table_arn       = module.dynamodb.approval_decisions_table_arn
  approval_table_name      = module.dynamodb.approval_decisions_table_name
  security_bus_arn         = module.eventbridge_bus.security_bus_arn
  security_bus_name        = module.eventbridge_bus.security_bus_name
  escalations_topic_arn    = module.sns_notifications.escalations_topic_arn
  incident_key_arn         = module.kms.incident_key_arn
  enable_lab_password_auth = var.enable_lab_environment
  tags                     = local.common_tags
}

module "verification" {
  source                = "./modules/verification"
  depends_on            = [module.observability]
  env_code              = local.env_code
  source_dir            = "${path.root}/../lambda"
  role_arn              = module.iam.verification_role_arn
  incidents_table_name  = module.dynamodb.incidents_table_name
  security_bus_name     = module.eventbridge_bus.security_bus_name
  security_bus_arn      = module.eventbridge_bus.security_bus_arn
  escalations_topic_arn = module.sns_notifications.escalations_topic_arn
  tags                  = local.common_tags
}

module "evidence_bucket" {
  source                       = "./modules/evidence-bucket"
  depends_on                   = [module.observability]
  env_code                     = local.env_code
  account_id                   = var.security_account_id
  evidence_key_arn             = module.kms.evidence_key_arn
  retention_days               = var.environment == "prod" ? 365 : 30
  noncurrent_transition_days   = var.environment == "prod" ? 90 : 30
  tags                         = local.common_tags
  source_dir                   = "${path.root}/../lambda"
  reporting_role_arn           = module.iam.reporting_role_arn
  incidents_table_name         = module.dynamodb.incidents_table_name
  remediation_audit_table_name = local.remediation_audit_table_name
  security_bus_name            = module.eventbridge_bus.security_bus_name
}

module "reporting" {
  source     = "./modules/reporting"
  depends_on = [module.observability]

  env_code             = local.env_code
  source_dir           = "${path.root}/../lambda"
  role_arn             = module.iam.reporting_role_arn
  evidence_bucket_name = module.evidence_bucket.bucket_name
  evidence_key_arn     = module.kms.evidence_key_arn
  reports_topic_arn    = module.sns_notifications.reports_topic_arn
  security_bus_name    = module.eventbridge_bus.security_bus_name
  tags                 = local.common_tags
}

module "knowledge_base" {
  source     = "./modules/knowledge-base"
  depends_on = [module.observability]

  env_code                  = local.env_code
  source_dir                = "${path.root}/../lambda"
  role_arn                  = module.iam.reporting_role_arn
  knowledge_base_table_name = module.dynamodb.knowledge_base_table_name
  security_bus_name         = module.eventbridge_bus.security_bus_name
  tags                      = local.common_tags
}

module "observability" {
  source = "./modules/cloudwatch"

  env_code             = local.env_code
  region               = var.region
  account_id           = var.security_account_id
  errors_topic_arn     = module.sns_notifications.errors_topic_arn
  state_machine_arn    = "arn:aws:states:${var.region}:${var.security_account_id}:stateMachine:${local.prefix}-remediation-executor"
  incidents_table_name = local.incidents_table_name
  findings_table_name  = local.findings_table_name
  dlq_name             = local.dlq_name
  log_retention_days   = var.environment == "prod" ? 365 : 30
  lambda_functions = {
    "${local.prefix}-guardduty-ingestor"      = 30
    "${local.prefix}-securityhub-ingestor"    = 30
    "${local.prefix}-config-ingestor"         = 30
    "${local.prefix}-correlation"             = 30
    "${local.prefix}-investigation"           = 90
    "${local.prefix}-safety-validation"       = 30
    "${local.prefix}-baseline-computation"    = 300
    "${local.prefix}-approval-handler"        = 30
    "${local.prefix}-approval-expiry"         = 60
    "${local.prefix}-remediation-framework"   = 30
    "${local.prefix}-verification-engine"     = 60
    "${local.prefix}-evidence-packager"       = 120
    "${local.prefix}-incident-reporting"      = 30
    "${local.prefix}-knowledge-base-ingestor" = 30
  }
  tags = local.common_tags
}

# =====================================================================
# PHASE 2 modules (Core Incident Platform)
# Wires after KMS + IAM so resource-scoped IAM policies already exist.
# =====================================================================

module "dynamodb" {
  source = "./modules/dynamodb"

  env_code                      = local.env_code
  incidents_table_name          = local.incidents_table_name
  findings_table_name           = local.findings_table_name
  baselines_table_name          = local.baselines_table_name
  decisions_table_name          = local.decisions_table_name
  idempotency_table_name        = local.idempotency_table_name
  remediation_audit_table_name  = local.remediation_audit_table_name
  approval_decisions_table_name = local.approval_decisions_table_name
  knowledge_base_table_name     = local.knowledge_base_table_name

  incident_key_arn = module.kms.incident_key_arn
  finding_key_arn  = module.kms.finding_key_arn

  disable_deletion_protection = contains(["dev", "demo"], var.environment)

  tags = local.common_tags
}

module "eventbridge_bus" {
  source     = "./modules/eventbridge"
  depends_on = [module.observability]

  env_code                  = local.env_code
  security_account_id       = var.security_account_id
  security_account_root_arn = "arn:aws:iam::${var.security_account_id}:root"

  security_bus_name = local.security_bus_name
  dlq_arn           = module.sqs_dlq.dlq_arn

  correlation_function_name       = local.correlation_engine_fn_name
  investigation_function_name     = local.investigation_fn_name
  safety_validation_function_name = local.safety_validation_fn_name
  correlation_role_arn            = module.iam.correlation_role_arn
  baseline_role_arn               = module.iam.correlation_role_arn
  baseline_reserved_concurrency   = var.baseline_reserved_concurrency
  incidents_table_name            = module.dynamodb.incidents_table_name
  findings_table_name             = module.dynamodb.findings_table_name
  baselines_table_name            = module.dynamodb.baselines_table_name
  decisions_table_name            = module.dynamodb.decisions_table_name
  security_bus_name_for_lambda    = local.security_bus_name
  baseline_function_name          = "${local.prefix}-baseline-computation"
  error_topic_arn                 = module.sns_notifications.errors_topic_arn
  investigation_role_arn          = module.iam.investigation_role_arn
  safety_validation_role_arn      = module.iam.safety_validation_role_arn

  tags = local.common_tags
}

module "sqs_dlq" {
  source = "./modules/sqs"

  env_code                  = local.env_code
  dlq_name                  = local.dlq_name
  finding_key_arn           = module.kms.finding_key_arn
  recovery_role_arn         = module.iam.recovery_role_arn
  terraform_deploy_role_arn = module.iam.terraform_deploy_role_arn
  correlation_role_arn      = module.iam.correlation_role_arn
  investigation_role_arn    = module.iam.investigation_role_arn
  ingestion_role_arn        = module.iam.ingestion_role_arn
  alarm_topic_arn           = module.sns_notifications.errors_topic_arn

  tags = local.common_tags
}

module "sns_notifications" {
  source = "./modules/sns"

  env_code                   = local.env_code
  incidents_topic_name       = local.incidents_topic_name
  escalations_topic_name     = local.escalations_topic_name
  errors_topic_name          = local.errors_topic_name
  reports_topic_name         = local.reports_topic_name
  incident_key_arn           = module.kms.incident_key_arn
  terraform_deploy_role_arn  = module.iam.terraform_deploy_role_arn
  correlation_role_arn       = module.iam.correlation_role_arn
  investigation_role_arn     = module.iam.investigation_role_arn
  safety_validation_role_arn = module.iam.safety_validation_role_arn
  verification_role_arn      = module.iam.verification_role_arn
  reporting_role_arn         = module.iam.reporting_role_arn
  ingestion_role_arn         = module.iam.ingestion_role_arn

  tags = local.common_tags
}

module "telemetry_ingestion" {
  source     = "./modules/telemetry-ingestion"
  depends_on = [module.observability]

  env_code                     = local.env_code
  source_dir                   = "${path.root}/../lambda"
  ingestion_role_arn           = module.iam.ingestion_role_arn
  findings_table_name          = module.dynamodb.findings_table_name
  security_bus_name            = module.eventbridge_bus.security_bus_name
  dlq_arn                      = module.sqs_dlq.dlq_arn
  dlq_url                      = module.sqs_dlq.dlq_url
  enable_guardduty_ingestion   = var.enable_guardduty_ingestion
  enable_securityhub_ingestion = var.enable_securityhub_ingestion
  enable_config_ingestion      = var.enable_config_ingestion
  reserved_concurrency         = var.telemetry_reserved_concurrency
  tags                         = local.common_tags
}

module "organization_cloudtrail" {
  count  = var.enable_organization_cloudtrail ? 1 : 0
  source = "./modules/cloudtrail"

  env_code            = local.env_code
  account_id          = var.security_account_id
  enable_object_lock  = var.enable_cloudtrail_object_lock
  retention_days      = var.cloudtrail_object_lock_retention_days
  tags                = local.common_tags
  source_dir          = "${path.root}/../lambda/ingestion"
  ingestion_role_arn  = module.iam.ingestion_role_arn
  findings_table_name = module.dynamodb.findings_table_name
  security_bus_name   = module.eventbridge_bus.security_bus_name
  dlq_url             = module.sqs_dlq.dlq_url
}

module "config_aggregator" {
  count  = var.enable_config_aggregator ? 1 : 0
  source = "./modules/awsconfig"

  env_code              = local.env_code
  organization_mode     = var.enable_organization_config_aggregation
  organization_role_arn = var.config_organization_role_arn
  account_ids           = length(var.telemetry_account_ids) > 0 ? var.telemetry_account_ids : [var.workload_account_id]
  regions               = var.telemetry_regions
  tags                  = local.common_tags
}

module "security_lake" {
  count  = var.enable_security_lake ? 1 : 0
  source = "./modules/securitylake"

  account_ids                 = length(var.telemetry_account_ids) > 0 ? var.telemetry_account_ids : [var.workload_account_id]
  regions                     = var.telemetry_regions
  meta_store_manager_role_arn = var.security_lake_meta_store_manager_role_arn
  tags                        = local.common_tags
}
