variable "env_code" {
  type = string
}
variable "security_account_id" {
  type = string
}
variable "monthly_budget_name" {
  type = string
}
variable "cost_alerts_topic_name" {
  type = string
}
variable "monthly_budget_limit" {
  description = "Monthly budget limit in USD. Dev = 50, staging = 200, prod = 500."
  type        = number
}
variable "project_name" {
  type = string
}
variable "environment" {
  type = string
}
variable "ssm_key_arn" {
  type = string
}
variable "alert_email" {
  description = "Optional email endpoint for cost-alert SNS notifications"
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.alert_email == null || can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.alert_email))
    error_message = "alert_email must be null or a valid email address."
  }
}
variable "tags" {
  type    = map(string)
  default = {}
}
