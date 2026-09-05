output "terraform_deploy_role_arn" {
  value = aws_iam_role.terraform_deploy.arn
}
output "ingestion_role_arn" {
  value = aws_iam_role.ingestion.arn
}
output "correlation_role_arn" {
  value = aws_iam_role.correlation.arn
}
output "investigation_role_arn" {
  value = aws_iam_role.investigation.arn
}
output "safety_validation_role_arn" {
  value = aws_iam_role.safety_validation.arn
}
output "remediation_role_arn" {
  value = aws_iam_role.remediation.arn
}
output "verification_role_arn" {
  value = aws_iam_role.verification.arn
}
output "reporting_role_arn" {
  value = aws_iam_role.reporting.arn
}
output "recovery_role_arn" {
  value = aws_iam_role.recovery.arn
}
output "security_admin_role_arn" {
  value = aws_iam_role.security_admin.arn
}
