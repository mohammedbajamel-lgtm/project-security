# CloudSec AI - SQS Module Variables
#
# Receives the DLQ name and role/key ARNs from the root composition.

variable "env_code" {
  description = "Short environment code: dev | stg | prd"
  type        = string
}

variable "dlq_name" {
  description = "Name of the DLQ queue"
  type        = string
}

variable "finding_key_arn" {
  description = "ARN of the finding KMS key for SSE-KMS on the DLQ"
  type        = string
}

variable "recovery_role_arn" {
  description = "ARN of the recovery role that may read from the DLQ"
  type        = string
}

variable "terraform_deploy_role_arn" {
  description = "ARN of the terraform deploy role (state operations)"
  type        = string
}

variable "correlation_role_arn" {
  description = "ARN of the correlation engine Lambda role"
  type        = string
}

variable "investigation_role_arn" {
  description = "ARN of the investigation engine Lambda role"
  type        = string
}

variable "ingestion_role_arn" {
  description = "ARN of the ingestion Lambda role"
  type        = string
}

variable "alarm_topic_arn" {
  description = "SNS topic ARN notified when the DLQ contains messages"
  type        = string
}

variable "tags" {
  description = "Base tags to merge into every resource"
  type        = map(string)
  default     = {}
}
