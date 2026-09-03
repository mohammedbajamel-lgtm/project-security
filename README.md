# CloudSec AI

AWS-native, serverless automated incident response platform.

Detect → Correlate → Investigate → Blast Radius → Safety Validate → Remediate → Verify → Report

## Quick Start

See `docs/development.md` for full local development setup.

## Repository Structure

```
terraform/        # Infrastructure as Code (Terraform 1.6+)
lambda/           # AWS Lambda functions (Python 3.11+)
tests/            # Unit, integration, and e2e test suites
schemas/          # JSON Schema definitions for all platform events
playbooks/        # Step Functions ASL remediation playbook definitions
docs/             # Architecture, runbooks, threat models
attack-simulations/  # Synthetic attack payloads for e2e testing
scripts/          # CI/CD and operational helpers
```

## Branch Protection Rules

All branches require the following before merge:

- **Pull request review required** — at least 1 approving review from a maintainer.
- **CI checks must pass** — lint, unit-test, and tfsec stages in `.github/workflows/ci.yml`.
- **No direct pushes to `main`** — all changes go through a PR.
- **Conversation resolution required** — all review comments must be resolved.
- **Branch up to date with `main`** — no stale merges.

These rules should be configured in the repository settings under
**Settings → Branches → Branch protection rules**.

## Development

```bash
# Install Python dependencies
python -m venv .venv
source .venv/bin/activate        # Linux/macOS
.venv\Scripts\activate           # Windows PowerShell
pip install -r requirements.txt

# Validate Terraform
terraform init
terraform validate
terraform plan -var-file=terraform/environments/dev/dev.tfvars.example

# Run tests
pytest tests/unit --cov=lambda --cov-report=term-missing
```

## Security

This repository follows strict security guardrails. See
`.kiro/steering/security.md` for the full set. Key principles:

- No AdministratorAccess for application components.
- Bedrock never directly calls AWS APIs.
- All remediation flows through deterministic safety validation.
- Evidence is encrypted, versioned, and tamper-evident.
