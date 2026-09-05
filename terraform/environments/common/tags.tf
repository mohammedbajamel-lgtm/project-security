# CloudSec AI - Mandatory Tags
#
# Enforced in two ways:
#   1. default_tags on every provider (automatically applied to all resources)
#   2. local.required_tags - explicit blocks that child modules SHOULD merge
#
# Tags marked MANDATORY must appear on every resource. Tags marked
# SECURITY-RESOURCE-ONLY are required only on security-relevant resources
# (KMS keys, incident/evidence tables, evidence buckets, IAM roles).
#
# Tag reference:
#   Project              [MANDATORY]       cloudsec-ai
#   Environment          [MANDATORY]       dev | staging | prod
#   ManagedBy            [MANDATORY]       terraform
#   CostCenter           [MANDATORY]       e.g., security
#   CreatedBy            [MANDATORY]       cloudsec-platform (or owner team)
#   IncidentClassification [SECURITY-ONLY]  security-incident
#   DataSensitivity      [SECURITY-ONLY]    PII | FINDINGS | EVIDENCE | CONFIG
#   ComplianceFramework  [SECURITY-ONLY]    CIS | SOC2 | HIPAA (when applicable)

locals {
  mandatory_tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "terraform"
    CostCenter  = var.cost_center
    CreatedBy   = var.created_by
  }

  security_resource_tags = merge(local.mandatory_tags, {
    IncidentClassification = "security-incident"
  })

  # Tags for incident/evidence tables and buckets (may hold PII/forensics)
  evidence_resource_tags = merge(local.security_resource_tags, {
    DataSensitivity = "EVIDENCE"
  })

  # Tags for findings tables (aggregated telemetry, no direct PII)
  findings_resource_tags = merge(local.security_resource_tags, {
    DataSensitivity = "FINDINGS"
  })
}
