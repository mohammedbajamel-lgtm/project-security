# Root outputs (mirrors module outputs for cross-stack / CI consumption)

output "kms_keys" {
  value = {
    incident = module.kms.incident_key_arn
    evidence = module.kms.evidence_key_arn
    finding  = module.kms.finding_key_arn
    ssm      = module.kms.ssm_key_arn
  }
  description = "KMS key ARNs"
}

output "iam_roles" {
  value = {
    terraform_deploy  = module.iam.terraform_deploy_role_arn
    ingestion         = module.iam.ingestion_role_arn
    correlation       = module.iam.correlation_role_arn
    investigation     = module.iam.investigation_role_arn
    safety_validation = module.iam.safety_validation_role_arn
    remediation       = module.iam.remediation_role_arn
    verification      = module.iam.verification_role_arn
    reporting         = module.iam.reporting_role_arn
    recovery          = module.iam.recovery_role_arn
    security_admin    = module.iam.security_admin_role_arn
  }
  description = "IAM role ARNs for every platform component"
}

output "cost_alerts_topic_arn" {
  value       = module.cost_controls.cost_alerts_topic_arn
  description = "SNS topic ARN for cost budget alerts"
}

output "cost_anomaly_monitor_arn" {
  value       = module.cost_controls.cost_anomaly_monitor_arn
  description = "Cost Explorer anomaly monitor ARN for CloudSec AI tagged spend"
}

output "monthly_budget_name" {
  value = module.cost_controls.monthly_budget_name
}
output "monthly_budget_limit" {
  value = local.monthly_budget_limit
}

output "auth_account_id" {
  value       = var.security_account_id
  description = "Authenticated Security Account ID"
}

# ---- Phase 2 outputs ----
output "incidents_table_arn" {
  value       = module.dynamodb.incidents_table_arn
  description = "ARN of the DynamoDB incidents table"
}

output "findings_table_arn" {
  value       = module.dynamodb.findings_table_arn
  description = "ARN of the DynamoDB findings table"
}

output "baselines_table_arn" {
  value       = module.dynamodb.baselines_table_arn
  description = "ARN of the behavior baselines table"
}

output "security_bus_arn" {
  value       = module.eventbridge_bus.security_bus_arn
  description = "ARN of the CloudSec AI custom EventBridge bus"
}

output "dlq_arn" {
  value       = module.sqs_dlq.dlq_arn
  description = "ARN of the CloudSec AI DLQ"
}

output "incidents_topic_arn" {
  value       = module.sns_notifications.incidents_topic_arn
  description = "ARN of the incident lifecycle notifications topic"
}

output "escalations_topic_arn" {
  value       = module.sns_notifications.escalations_topic_arn
  description = "ARN of the escalation alerts topic"
}

output "errors_topic_arn" {
  value       = module.sns_notifications.errors_topic_arn
  description = "ARN of the system error notifications topic"
}

output "reports_topic_arn" {
  value       = module.sns_notifications.reports_topic_arn
  description = "ARN of the stakeholder incident reports topic"
}

output "reporting_function_name" {
  value       = module.reporting.function_name
  description = "Name of the terminal incident reporting Lambda"
}

output "knowledge_base_table_arn" {
  value       = module.dynamodb.knowledge_base_table_arn
  description = "ARN of the verified incident knowledge-base table"
}

output "knowledge_base_function_name" {
  value       = module.knowledge_base.function_name
  description = "Name of the verified incident knowledge-base ingestor"
}

output "telemetry_ingestor_function_names" {
  value = module.telemetry_ingestion.function_names
}

output "organization_cloudtrail_arn" {
  value = try(module.organization_cloudtrail[0].trail_arn, null)
}

output "config_aggregator_arn" {
  value = try(module.config_aggregator[0].aggregator_arn, null)
}

output "security_lake_arn" {
  value = try(module.security_lake[0].data_lake_arn, null)
}
