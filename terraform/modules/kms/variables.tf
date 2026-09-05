variable "env_code" {
  description = "Short environment code: dev | stg | prd"
  type        = string
}

variable "security_account_id" {
  description = "AWS account ID of the Security Account"
  type        = string
}

variable "terraform_deploy_role_arn" {
  description = "IAM role ARN used to deploy the platform (T01-07 output)"
  type        = string
}

variable "correlation_role_arn" {
  type = string
}
variable "investigation_role_arn" {
  type = string
}
variable "safety_validation_role_arn" {
  type = string
}
variable "remediation_role_arn" {
  type = string
}
variable "verification_role_arn" {
  type = string
}
variable "reporting_role_arn" {
  type = string
}
variable "ingestion_role_arn" {
  type = string
}
variable "recovery_role_arn" {
  type = string
}

variable "incident_key_alias" {
  type = string
}
variable "evidence_key_alias" {
  type = string
}
variable "finding_key_alias" {
  type = string
}
variable "ssm_key_alias" {
  type = string
}

variable "tags" {
  description = "Base tags to merge into every key"
  type        = map(string)
  default     = {}
}
