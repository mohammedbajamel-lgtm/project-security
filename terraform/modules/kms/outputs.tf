output "incident_key_id" {
  value       = aws_kms_key.incident_key.key_id
  description = "Key ID for the incident key"
}
output "incident_key_arn" {
  value       = aws_kms_key.incident_key.arn
  description = "ARN for the incident key"
}
output "incident_key_alias" {
  value = aws_kms_alias.incident_key.name
}

output "evidence_key_id" {
  value = aws_kms_key.evidence_key.key_id
}
output "evidence_key_arn" {
  value = aws_kms_key.evidence_key.arn
}
output "evidence_key_alias" {
  value = aws_kms_alias.evidence_key.name
}

output "finding_key_id" {
  value = aws_kms_key.finding_key.key_id
}
output "finding_key_arn" {
  value = aws_kms_key.finding_key.arn
}
output "finding_key_alias" {
  value = aws_kms_alias.finding_key.name
}

output "ssm_key_id" {
  value = aws_kms_key.ssm_key.key_id
}
output "ssm_key_arn" {
  value = aws_kms_key.ssm_key.arn
}
output "ssm_key_alias" {
  value = aws_kms_alias.ssm_key.name
}
