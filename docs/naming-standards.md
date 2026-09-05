# CloudSec AI — Naming & Tagging Standards

## Resource Name Pattern

```
cloudsec-{env_short}-{component}[-{suffix}]
```

- **env_short:** `dev` | `stg` | `prd`
- **component:** kebab-case short name of the subsystem (e.g., `correlation`, `findings`)
- **suffix:** only when needed for uniqueness (e.g., random hex on S3 bucket names, KMS key ARN suffixes). Do NOT append suffixes for readability — rely on tags for disambiguation.

## Tag Requirements

| Tag | Scope | Required values |
|-----|-------|-----------------|
| `Project` | ALL resources | `cloudsec-ai` |
| `Environment` | ALL resources | `dev` \| `staging` \| `prod` |
| `ManagedBy` | ALL resources | `terraform` (or `manual` for one-off ops) |
| `CostCenter` | ALL resources | e.g., `security` |
| `CreatedBy` | ALL resources | `cloudsec-platform` (or owner team name) |
| `IncidentClassification` | Security resources | `security-incident` |
| `DataSensitivity` | Data stores | `FINDINGS` \| `EVIDENCE` \| `PII` \| `CONFIG` |
| `ComplianceFramework` | Only if scoped | `CIS` \| `SOC2` \| `HIPAA` |

### Enforcement

- `default_tags` on every Terraform provider apply the mandatory tags to every
  resource automatically.
- `local.required_tags` in `terraform/environments/common/tags.tf` is the
  explicit list that child modules SHOULD merge into their own `tags` blocks.

## Resource Name Examples

### S3

| Purpose | Name |
|---------|------|
| Terraform state backend | `cloudsec-{env_short}-terraform-state-{random}` |
| Evidence preservation bucket | `cloudsec-{env_short}-evidence` |
| CloudFormation/CloudTrail logs | `cloudsec-{env_short}-logs` |

### DynamoDB

| Purpose | Name |
|---------|------|
| Incidents (partition + sort key) | `cloudsec-{env_short}-incidents` |
| Normalized findings | `cloudsec-{env_short}-findings` |

### SQS

| Purpose | Name |
|---------|------|
| Dead-letter queue | `cloudsec-{env_short}-dlq` |
| Correlation ingestion queue | `cloudsec-{env_short}-correlation` |
| Ingestion fanout queue | `cloudsec-{env_short}-ingestion` |

### SNS

| Purpose | Name |
|---------|------|
| Incident lifecycle notifications | `cloudsec-{env_short}-incidents` |
| Escalation notifications | `cloudsec-{env_short}-escalations` |
| System errors | `cloudsec-{env_short}-errors` |
| Cost alerts | `cloudsec-{env_short}-cost-alerts` |

### EventBridge

| Purpose | Name |
|---------|------|
| Custom security event bus | `cloudsec-{env_short}-security-bus` |

### KMS Aliases

| Purpose | Alias |
|---------|-------|
| Incident data encryption | `alias/cloudsec/{env}/incident` |
| Evidence bucket encryption | `alias/cloudsec/{env}/evidence` |
| Findings encryption | `alias/cloudsec/{env}/finding` |
| SSM parameters encryption | `alias/cloudsec/{env}/ssm` |

### IAM

| Purpose | Role name |
|---------|-----------|
| Terraform deploy role | `cloudsec-{env_short}-terraform-deploy` |
| Correlation engine | `cloudsec-{env_short}-correlation-role` |
| Investigation engine | `cloudsec-{env_short}-investigation-role` |
| Safety validation | `cloudsec-{env_short}-safety-validation-role` |
| Remediation executor | `cloudsec-{env_short}-remediation-role` |
| Verification engine | `cloudsec-{env_short}-verification-role` |
| Reporting | `cloudsec-{env_short}-reporting-role` |
| Ingestor (shared) | `cloudsec-{env_short}-ingestion-role` |
| DLQ recovery | `cloudsec-{env_short}-recovery-role` |
| Security admin (break-glass) | `cloudsec-{env_short}-security-admin-role` |

### Lambda

| Purpose | Function name |
|---------|---------------|
| GuardDuty ingestor | `cloudsec-{env_short}-guardduty-ingestor` |
| Security Hub ingestor | `cloudsec-{env_short}-securityhub-ingestor` |
| CloudTrail ingestor | `cloudsec-{env_short}-cloudtrail-ingestor` |
| VPC Flow Log ingestor | `cloudsec-{env_short}-vpcflow-ingestor` |
| Config ingestor | `cloudsec-{env_short}-config-ingestor` |
| Correlation engine | `cloudsec-{env_short}-correlation` |
| Investigation | `cloudsec-{env_short}-investigation` |
| Safety validation | `cloudsec-{env_short}-safety-validation` |
| Verification | `cloudsec-{env_short}-verification` |
| Reporting | `cloudsec-{env_short}-reporting` |

### Step Functions

| Purpose | State machine name |
|---------|--------------------|
| Investigation workflow | `cloudsec-{env_short}-investigation-sm` |
| Remediation workflow | `cloudsec-{env_short}-remediation-sm` |

## Conventions

- **No underscores** in resource names (use hyphens).
- **No environment in the ARN** — the account ID already scopes the resource;
  the environment is captured by the `Environment` tag.
- **No hardcoded region** in names; regions are part of provider config.
- **Never** include secrets, customer data, or PII in names/tags.
- **Do not** reuse a name across environments — they must not collide if the
  same module is applied in dev and prod.
