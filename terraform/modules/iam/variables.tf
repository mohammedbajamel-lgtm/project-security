# ---- Environment ----
variable "env_code" {
  type = string
}
variable "security_account_id" {
  type = string
}
variable "region" {
  type = string
}

# ---- Naming ----
variable "terraform_deploy_role_name" {
  type = string
}
variable "ingestion_role_name" {
  type = string
}
variable "correlation_role_name" {
  type = string
}
variable "investigation_role_name" {
  type = string
}
variable "safety_validation_role_name" {
  type = string
}
variable "remediation_role_name" {
  type = string
}
variable "verification_role_name" {
  type = string
}
variable "reporting_role_name" {
  type = string
}
variable "recovery_role_name" {
  type = string
}
variable "security_admin_role_name" {
  type = string
}

# ---- Assume-role principals ----
variable "allowed_terraform_principals" {
  description = "IAM user/role ARNs allowed to assume the TerraformDeploy role"
  type        = list(string)
}
variable "allowed_security_admin_principals" {
  description = "IAM user/role ARNs allowed to assume the security-admin break-glass role"
  type        = list(string)
}

# ---- Resource ARNs consumed by the policies ----
variable "incidents_table_arn" {
  type = string
}
variable "findings_table_arn" {
  type = string
}
variable "baselines_table_arn" {
  type = string
}
variable "decisions_table_arn" { type = string }
variable "idempotency_table_arn" { type = string }
variable "remediation_audit_table_arn" { type = string }
variable "knowledge_base_table_arn" { type = string }
variable "evidence_bucket_arn" {
  type = string
}
variable "cloudtrail_bucket_arn" {
  type = string
}
variable "security_bus_arn" {
  type = string
}
variable "dlq_arn" {
  type = string
}
variable "incidents_topic_arn" {
  type = string
}
variable "escalations_topic_arn" {
  type = string
}
variable "reports_topic_arn" {
  type = string
}

# ---- KMS key ARNs ----
variable "incidents_key_arn" {
  type = string
}
variable "evidence_key_arn" {
  type = string
}
variable "finding_key_arn" {
  type = string
}
variable "ssm_key_arn" {
  type = string
}

# ---- Bedrock ----
variable "bedrock_model_arns" {
  description = "Exact ARNs for the Bedrock inference profile and its backing models"
  type        = list(string)
}

# ---- Tags ----
variable "tags" {
  type    = map(string)
  default = {}
}
