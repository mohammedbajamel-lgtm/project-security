# CloudSec AI - EventBridge Module Variables
#
# Used by both the security bus (T02-03) and the routing rules (T02-08).

variable "env_code" {
  description = "Short environment code: dev | stg | prd"
  type        = string
}

variable "security_account_id" {
  description = "AWS account ID of the Security Account"
  type        = string
}

variable "security_account_root_arn" {
  description = "ARN of the Security Account root principal for bus policy scope"
  type        = string
}

variable "security_bus_name" {
  description = "Name of the custom security event bus"
  type        = string
}

variable "dlq_arn" {
  description = "ARN of the DLQ used for failed rule invocations (T02-04)"
  type        = string
}

variable "correlation_function_name" {
  type = string
}

variable "investigation_function_name" {
  type = string
}

variable "safety_validation_function_name" {
  type = string
}

variable "correlation_role_arn" {
  type = string
}

variable "incidents_table_name" { type = string }
variable "findings_table_name" { type = string }
variable "security_bus_name_for_lambda" { type = string }
variable "baseline_function_name" { type = string }
variable "baseline_role_arn" { type = string }
variable "baseline_reserved_concurrency" { type = number }
variable "baselines_table_name" { type = string }
variable "decisions_table_name" { type = string }
variable "error_topic_arn" { type = string }

variable "investigation_role_arn" {
  type = string
}

variable "safety_validation_role_arn" {
  type = string
}

variable "tags" {
  description = "Base tags to merge into every resource"
  type        = map(string)
  default     = {}
}
