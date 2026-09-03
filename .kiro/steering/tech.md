---
inclusion: always
---

# CloudSec AI — Tech Stack

## Languages & Runtimes

| Component         | Tech                              |
|-------------------|-----------------------------------|
| Lambda functions  | Python 3.11+                      |
| Infrastructure    | HashiCorp Terraform 1.6+          |
| Orchestrator      | AWS Step Functions (ASL)          |
| AI models         | Amazon Bedrock — Claude 3.5 Sonnet |
| Event bus         | Amazon EventBridge                |
| Evidence store    | S3 (encrypted, versioned, Object Lock in prod) |

## Core Libraries (Python)

- **boto3 / botocore** — AWS SDK. All Lambda-to-AWS calls go through these.
- **jsonschema** — Strict validation of AI-generated recommendation objects against JSON Schema definitions.
- **jinja2** — Template rendering for prompt construction and report generation.
- **requests** — HTTP client for external API calls and S3 presigned URL handling.
- **hypothesis** — *(Optional, Phase 5+)* Property-based testing for validation and correlation logic; not part of Phase 1 base dependencies.
- **botocore** — Low-level client construction for cross-account role assumption via `sts:AssumeRole`.

## Testing

- **pytest** — Primary test runner.
- **pytest-cov** — Coverage enforcement (min 90% on core modules).
- **moto** — Local AWS service mocking for unit tests.
- **AWS SDK (boto3) stubs** — Alternative to moto for isolated tests.

## Infrastructure

- Terraform with module per AWS service (eventbridge, lambdas, step-functions, evidence-bucket).
- Terraform backend: S3 bucket + DynamoDB state lock table (per environment).
- Environments managed via `.tfvars` files; `backend` blocks overridden per env.
- **tflint** enforced; no wildcard IAM actions.

## Secrets & KMS

- Sensitive values via AWS Secrets Manager; KMS customer-managed keys encrypt S3, DynamoDB, and Lambda environment variables.

## Common Commands

| Task             | Command                                                    |
|------------------|------------------------------------------------------------|
| Init Terraform   | `terraform init -backend-config=s3-backend-config.hcl`     |
| Validate TF plan | `terraform validate && terraform plan -var-file=dev.tfvars`|
| Apply infra      | `terraform apply -var-file=dev.tfvars`                     |
| Lint TF          | `tflint -f compact`                                        |
| Run unit tests   | `pytest tests/unit --cov=lambda --cov-report=term-missing` |
| Run integration  | `pytest tests/integration -m integration`                  |
| Run e2e          | `pytest tests/e2e -m e2e`                                  |
