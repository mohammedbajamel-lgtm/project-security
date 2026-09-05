# CloudSec AI - SNS Module Variables

variable "env_code" {
  description = "Short environment code: dev | stg | prd"
  type        = string
}

variable "incidents_topic_name" {
  description = "Name of the incidents topic"
  type        = string
}

variable "escalations_topic_name" {
  description = "Name of the escalations topic"
  type        = string
}

variable "errors_topic_name" {
  description = "Name of the errors topic"
  type        = string
}

variable "reports_topic_name" {
  description = "Name of the stakeholder incident reports topic"
  type        = string
}

variable "incident_key_arn" {
  description = "ARN of the incident KMS key for SSE-KMS"
  type        = string
}

variable "terraform_deploy_role_arn" {
  description = "ARN of the terraform deploy role (can subscribe)"
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

variable "safety_validation_role_arn" {
  description = "ARN of the safety-validation Lambda role"
  type        = string
}

variable "verification_role_arn" {
  description = "ARN of the verification engine Lambda role"
  type        = string
}

variable "reporting_role_arn" {
  description = "ARN of the reporting Lambda role"
  type        = string
}

variable "ingestion_role_arn" {
  description = "ARN of the ingestion Lambda role"
  type        = string
}

variable "tags" {
  description = "Base tags to merge into every resource"
  type        = map(string)
  default     = {}
}
