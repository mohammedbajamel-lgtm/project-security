# CloudSec AI — Development Setup

## Prerequisites

- Python 3.11+ (see `.python-version`)
- Terraform 1.6+ (see `.terraform-version`)
- AWS CLI configured with appropriate credentials
- Git

## Quick Start

```bash
# 1. Create and activate virtual environment
python -m venv .venv
# Linux / macOS:
source .venv/bin/activate
# Windows PowerShell:
.venv\Scripts\activate

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Initialize Terraform
terraform init -backend-config=terraform/environments/dev/backend.hcl

# 4. Validate Terraform configuration
terraform validate

# 5. Plan changes
terraform plan -var-file=terraform/environments/dev/dev.tfvars

# 6. Run unit tests
pytest tests/unit --cov=lambda --cov-report=term-missing
```

## AWS Configuration

Use AWS SSO for authentication — never hardcode access keys:

```bash
aws sso login --profile cloudsec-dev
export AWS_PROFILE=cloudsec-dev
```

## Environment Files

| Environment | Config File              | Object Lock | Budget Limit |
|-------------|--------------------------|-------------|--------------|
| dev         | `dev/dev.tfvars`         | false       | $100/month   |
| staging     | `staging/staging.tfvars` | false       | $500/month   |
| prod        | `prod/prod.tfvars`       | true        | $2000/month  |

Copy `*.tfvars.example` to `*.tfvars` and fill in real values.
Never commit `*.tfvars` files with real secrets.

## Directory Layout

See `.kiro/steering/structure.md` for the full approved directory tree.

## Security

See `.kiro/steering/security.md` for all security guardrails. Key reminders:

- Never use AdministratorAccess.
- Bedrock never directly calls AWS APIs.
- Run `terraform apply` only with explicit approval.
- Never hardcode credentials, secrets, or account IDs.
