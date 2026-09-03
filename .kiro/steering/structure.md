---
inclusion: always
---

# CloudSec AI — Project Structure

```
cloudsec-ai/
├── terraform/
│   ├── backend/                  # T01-02: S3 bucket + DynamoDB state lock table
│   ├── modules/
│   │   ├── eventbridge/          # Event bus + rules (per environment)
│   │   ├── lambdas/              # Lambda deployment package modules
│   │   ├── step-functions/       # Step Functions state machine definitions
│   │   ├── dynamodb/             # Incident and findings tables (T02-01, T02-02)
│   │   ├── sqs/                  # Dead letter queue + processing queues (T02-04)
│   │   ├── sns/                  # Notification topics (T02-07)
│   │   ├── evidence-bucket/      # S3 evidence store with KMS + Object Lock
│   │   ├── kms/                  # KMS key pairs
│   │   ├── iam/                  # Cross-account role modules
│   │   └── cost-controls/        # Budgets + anomaly detection (T01-08)
│   ├── environments/
│   │   ├── common/               # Providers, variables, locals, naming, tags (T01-03, T01-05)
│   │   ├── dev/                  # dev.tfvars + backend config
│   │   ├── staging/
│   │   └── prod/                 # prod.tfvars + S3 Object Lock enabled
│   └── main.tf                   # Root module composing all sub-modules
├── lambda/
│   ├── ingestion/                # T03: GuardDuty, Security Hub, CloudTrail, Config ingestors
│   │   ├── guardduty_ingestor.py
│   │   ├── securityhub_ingestor.py
│   │   ├── cloudtrail_ingestor.py
│   │   └── normalizer.py
│   ├── correlation-engine/       # T04: GuardDuty → correlation → EventBridge
│   │   └── main.py
│   ├── investigation-engine/     # T06: Bedrock invocation + prompt assembly
│   │   └── main.py
│   ├── safety-validation/        # T09: Deterministic allow/deny gate
│   │   └── main.py
│   ├── verification-engine/      # T13: Post-remediation state checks
│   │   └── main.py
│   ├── reporting/                # T15: AI-assisted incident report generation
│   │   └── main.py
│   ├── behavior-baseline/        # T05: Statistical baseline computation (design.md §25)
│   │   └── main.py
│   ├── knowledge-base/           # T16: Confirmed incident storage and retrieval (design.md §22)
│   │   └── main.py
│   ├── blast-radius/             # Design.md §13: Blast radius computation
│   │   └── main.py
│   ├── attack-timeline/          # Design.md §12: Temporal reconstruction
│   │   └── main.py
│   ├── mitre-mapping/            # Design.md §13: MITRE ATT&CK technique mapping
│   │   └── main.py
│   ├── playbook-executor/        # T11: Step Functions orchestration
│   │   └── main.py
│   └── shared/                   # Common utilities importable via sys.path
├── schemas/
│   ├── common-types.json         # T02-05: AccountId, Arn, IpAddress, Timestamp, Severity, Status
│   ├── finding-event.json        # T02-05: FindingIngested event
│   ├── incident-event.json       # T02-05: IncidentCreated, IncidentStatusChanged
│   ├── investigation-event.json  # T02-05: InvestigationStarted, InvestigationCompleted
│   ├── remediation-event.json    # T02-05: RemediationExecuted, RemediationVerified, RemediationFailed
│   ├── ai-recommendation.json    # Design.md §10: Platform Investigation Schema (supplementary)
│   ├── mitigation-response.json  # Design.md §14: Safety Validation Engine output (supplementary)
│   └── incident-report.json      # Design.md §23: Final incident report schema (supplementary)
├── tests/
│   ├── unit/                     # moto/boto3-stubbed, hypothesis-driven
│   ├── integration/              # Cross-Lambda via Step Functions test harness
│   └── e2e/                      # Full lifecycle against staging
├── playbooks/                    # Step Functions ASL definitions (6 scenarios)
│   ├── iam-credential-compromise.asl.json
│   ├── security-group-open.asl.json
│   ├── s3-public-bucket.asl.json
│   ├── compromised-ec2.asl.json
│   ├── cloudtrail-tampering.asl.json
│   └── iam-privilege-escalation.asl.json
├── docs/
│   ├── architecture/             # System design docs
│   ├── runbooks/                 # Operator playbooks
│   └── threat-models/            # Per-scenario threat models
├── attack-simulations/           # Synthetic attack payloads for e2e
│   └── iam-compromise/
└── scripts/
    ├── deploy.sh                 # CI/CD helper
    └── generate-evidence-report.py
```

## Naming Conventions

- **S3 buckets**: `cloudsec-{env}-{account}-evidence-{unique-id}`
- **IAM roles**: `cloudsec-{env}-{component}-{action}` (e.g. `cloudsec-prod-safety-validation-exec`)
- **EventBridge event names**: `CloudSec.{Environment}.{Component}.{Action}` (e.g. `CloudSec.Prod.CorrelationEngine.CreatingIncident`)
- **Step Functions**: `CloudSec-{env}-{playbook-name}` (e.g. `CloudSec-Prod-IAMCredentialCompromise`)

## Directory Rules

- Every Lambda lives in its own `lambda/<component>/` directory with a single `main.py` entry point.
- Shared utilities go in `lambda/shared/` — importable via `sys.path` or deployment package.
- Schemas are the source of truth; validate ALL external inputs and AI outputs against them before processing.
- `terraform/environments/common/` holds shared provider config, variables, locals, naming and tag definitions.
- `terraform/environments/` holds env-specific `.tfvars` and backend configs — never hardcode env values in modules.
- Playbooks are authored as ASL JSON in `playbooks/` and referenced by Terraform via `file()` function.
