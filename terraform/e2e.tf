# Phase 19 lab-only E2E configuration. The harness refuses non-lab names and
# validates the caller account before it performs any operation.
locals {
  e2e_parameters = var.enable_lab_environment ? {
    account_id                = var.security_account_id
    region                    = var.region
    environment               = var.environment
    resource_prefix           = local.prefix
    findings_table            = module.dynamodb.findings_table_name
    incidents_table           = module.dynamodb.incidents_table_name
    decisions_table           = module.dynamodb.decisions_table_name
    approval_decisions_table  = module.dynamodb.approval_decisions_table_name
    idempotency_table         = module.dynamodb.idempotency_table_name
    remediation_audit_table   = module.dynamodb.remediation_audit_table_name
    event_bus                 = module.eventbridge_bus.security_bus_name
    dlq_url                   = module.sqs_dlq.dlq_url
    evidence_bucket           = module.evidence_bucket.bucket_name
    state_machine_arn         = module.stepfunctions.state_machine_arn
    approval_api_url          = module.approval.api_url
    approval_user_pool_id     = module.approval.user_pool_id
    approval_client_id        = module.approval.user_pool_client_id
    guardduty_function        = module.telemetry_ingestion.function_names["guardduty"]
    securityhub_function      = module.telemetry_ingestion.function_names["securityhub"]
    cross_account_correlation = "false"
    scenario_timeout_seconds  = "600"
  } : {}
}

resource "aws_ssm_parameter" "e2e" {
  for_each = local.e2e_parameters

  name   = "/cloudsec/lab/e2e/${each.key}"
  type   = "SecureString"
  key_id = module.kms.ssm_key_arn
  value  = each.value

  tags = merge(local.common_tags, {
    Component = "phase19-e2e"
  })
}
