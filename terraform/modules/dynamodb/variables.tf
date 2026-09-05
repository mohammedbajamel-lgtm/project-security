# CloudSec AI - DynamoDB Module Variables
#
# Receives table names, KMS key ARNs, and tagging from the root composition.
# Table names come from local naming (never hardcoded inside modules).

variable "env_code" {
  description = "Short environment code: dev | stg | prd"
  type        = string
}

variable "incidents_table_name" {
  description = "Name of the incidents table (from local.incidents_table_name)"
  type        = string
}

variable "findings_table_name" {
  description = "Name of the findings table (from local.findings_table_name)"
  type        = string
}

variable "baselines_table_name" {
  description = "Name of the behavior baselines table"
  type        = string
}
variable "decisions_table_name" { type = string }
variable "idempotency_table_name" { type = string }
variable "remediation_audit_table_name" { type = string }
variable "approval_decisions_table_name" { type = string }
variable "knowledge_base_table_name" { type = string }

variable "incident_key_arn" {
  description = "ARN of the KMS incident key (T01-06 output)"
  type        = string
}

variable "finding_key_arn" {
  description = "ARN of the KMS finding key (T01-06 output)"
  type        = string
}

variable "tags" {
  description = "Base tags to merge into every resource"
  type        = map(string)
  default     = {}
}

variable "disable_deletion_protection" {
  description = "When true (dev only), disables DynamoDB deletion protection so resources can be torn down for cleanup."
  type        = bool
  default     = true
}
