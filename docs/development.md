# CloudSec AI — Development Environment

## Prerequisites

- **Python 3.11+** (Lambda runtime target is 3.11).
- **Terraform >= 1.6** (see `.terraform-version`).
- **AWS CLI v2** with a dev-privileged IAM user or SSO role.
- **Docker** (optional; only for localstack-based integration tests).
- **jq** (optional; used in some shell scripts).

## Environment Setup

```bash
# 1. Create the virtual environment
python3.11 -m venv .venv
source .venv/bin/activate

# 2. Install dependencies (runtime + dev)
pip install -e '.[dev,security]'

# 3. Pin Terraform (use tfenv, asdf, or HashiCorp CLI)
tfenv install $(cat .terraform-version)
tfenv use $(cat .terraform-version)

# 4. Verify
python -m pytest --version
terraform version
python -c "import boto3, pytest, jsonschema; print('ok')"
```

## AWS Credential Configuration

### Dev profile (recommended)

Configure a dedicated dev profile. **Do NOT** point it at production roles.

```bash
aws configure --profile cloudsec-dev
#   AWS Access Key ID [****]:     <dev user or SSO access key>
#   AWS Secret Access Key [****]: <dev secret>
#   Default region name [****]:   us-east-1
#   Default output format [****]: json
```

For SSO-based dev access:

```bash
aws sso login --profile cloudsec-dev \
    --sso-region us-east-1 \
    --start-url <org-sso-start-url>
```

### Terraform provider authentication

The Terraform providers in `terraform/environments/common/providers.tf` use
STS `assume_role` on role ARNs supplied by the environment tfvars. The
Terraform running identity (`cloudsec-dev` profile in the examples above) must
have permission to assume each target role. The dev IAM user is expected to
assume only the **dev** security-account and workload-account roles.

### Never

- Commit real tfvars.
- Hardcode access keys in code, CI, or Terraform.
- Point the dev profile at production roles.

## Terraform Workflow

```bash
# Initialize (uses S3 backend created by T01-02)
cd terraform
terraform init -backend-config=environments/dev/backend.hcl

# Plan
terraform plan -var-file=environments/dev/dev.tfvars

# Apply (requires approval gates for new resource types)
terraform apply -var-file=environments/dev/dev.tfvars

# Validate without AWS access (lint / schema only)
terraform validate
```

## Python Tests

```bash
# Unit tests only (fast, no AWS)
pytest tests/unit --maxfail=1

# Unit + integration tests (uses moto, may need docker for localstack)
pytest tests/unit tests/integration --maxfail=1

# Security lint
ruff check lambda/ tests/
bandit -r lambda/ -ll

# Type check
mypy lambda/
```

## Directory Layout

```
project/
├── terraform/
│   ├── backend/                          # Bootstrap S3 backend (T01-02)
│   ├── modules/                          # Reusable Terraform modules
│   │   ├── iam/
│   │   ├── kms/
│   │   ├── dynamodb/
│   │   ├── eventbridge/
│   │   ├── sqs/
│   │   ├── sns/
│   │   ├── lambda/
│   │   ├── stepfunctions/
│   │   ├── s3/
│   │   └── cost-controls/
│   ├── environments/
│   │   ├── common/                       # providers.tf, variables.tf, locals.tf
│   │   ├── dev/
│   │   ├── staging/
│   │   └── prod/
│   └── main.tf                           # Root composition (imports modules)
├── lambda/
│   ├── common/                           # Shared library (state machine, models, clients)
│   ├── ingestion/                        # Phase 3 ingestors (GuardDuty, SecHub, ...)
│   ├── correlation-engine/
│   ├── investigation-engine/
│   ├── safety-validation/
│   ├── verification-engine/
│   └── reporting/
├── tests/
│   ├── unit/
│   ├── integration/
│   └── e2e/
├── schemas/                              # JSON Schema definitions (T02-05)
├── docs/
├── scripts/
├── pyproject.toml
├── .terraform-version
├── .python-version
└── README.md
```

## Local Development Patterns

- **No AWS access required:** unit tests run with `moto` mocking of DynamoDB,
  SQS, SNS, S3, and KMS. All `boto3.client()` calls in Lambda code must
  accept an injected client so tests can substitute moto clients.
- **Terraform plan-only validation:** before any `apply`, run `terraform plan`
  and attach the plan output to the PR / review.
- **State management:** S3 backend with `use_lockfile = true`. Never delete
  state files directly; use `terraform state rm` or restore from backups.
- **Branch protection:** main branch requires PR review + passing CI (lint,
  unit tests, `terraform validate`, tfsec).

## Cost Controls

Budget alerts are deployed as part of T01-08. Until then, monitor dev spend
via the AWS Cost Explorer filter `Environment=dev AND Project=cloudsec-ai`.
