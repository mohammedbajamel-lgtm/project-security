variable "env_code" { type = string }
variable "source_dir" { type = string }
variable "ingestion_role_arn" { type = string }
variable "findings_table_name" { type = string }
variable "security_bus_name" { type = string }
variable "dlq_arn" { type = string }
variable "dlq_url" { type = string }
variable "enable_guardduty_ingestion" { type = bool }
variable "enable_securityhub_ingestion" { type = bool }
variable "enable_config_ingestion" { type = bool }
variable "tags" { type = map(string) }
variable "reserved_concurrency" {
  type    = number
  default = -1
  validation {
    condition     = var.reserved_concurrency == -1 || var.reserved_concurrency >= 1
    error_message = "Reserved concurrency must be -1 (unreserved) or at least 1."
  }
}
