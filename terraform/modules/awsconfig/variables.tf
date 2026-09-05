variable "env_code" { type = string }
variable "organization_mode" { type = bool }
variable "organization_role_arn" {
  type    = string
  default = null
}
variable "account_ids" { type = list(string) }
variable "regions" { type = list(string) }
variable "tags" { type = map(string) }
