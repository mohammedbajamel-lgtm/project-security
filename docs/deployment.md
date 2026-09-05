# Deployment guide

> Deploy into dedicated AWS accounts. Review every saved plan. Never point lab/demo variables at production.

## Prerequisites

AWS CLI v2, Terraform matching `.terraform-version`, Python matching `.python-version`, Git, AWS SSO with MFA, and separate Security, Workload, and Lab account IDs. Establish budget notifications and least-privilege deployment roles before billable services.

## Configure

1. Authenticate: `aws sso login --profile <profile>` and verify `aws sts get-caller-identity`.
2. Build the backend from `terraform/backend`, review its plan, apply it, and copy its output into `backend.hcl`.
3. Copy `terraform/environments/<env>/<env>.tfvars.example` to the untracked `.tfvars` file. Set account IDs, role ARNs, region, alert endpoint, retention, and concurrency.
4. Keep separate `TF_DATA_DIR` directories for each environment.

## Safe Terraform workflow

```bash
export TF_DATA_DIR="$PWD/terraform/.terraform-<env>"
terraform -chdir=terraform init -reconfigure -backend-config=environments/<env>/backend.hcl
terraform -chdir=terraform fmt -check -recursive
terraform -chdir=terraform validate
terraform -chdir=terraform plan -var-file=environments/<env>/<env>.tfvars -out=tfplan-<env>.binary
terraform -chdir=terraform show -no-color tfplan-<env>.binary
terraform -chdir=terraform apply tfplan-<env>.binary
```

Deploy in phase order: foundation (1), core data/eventing (2), telemetry (3), correlation/baselines (4–5), investigation/reconstruction/blast radius (6–8), safety (9), workflow/playbooks/approval/verification (10–13), evidence/reporting/knowledge (14–16), observability (17), lab only (18), tests (19), documentation/demo (20). Typical phases take 5–15 minutes; telemetry, identity, evidence retention, and end-to-end validation can take 15–30 minutes.

After each phase, run formatting, validation, unit tests, inspect outputs/logs/alarms, and perform the phase verification checkpoint. A rollback uses a newly reviewed Terraform plan that reverts the phase change; never apply an old plan after state changes.

## Multi-account setup

Use AWS SSO profiles and explicit deploy/telemetry roles. Trust policies name the Security Account or exact organization/account principals. Add one workload at a time and test denied access in both directions.

## Hard-to-delete resources

KMS deletion has a mandatory waiting period. S3 Object Lock can make retained versions undeletable. CloudTrail must stop before its storage is removed. Preserve required forensic data before rollback or destroy. See [cleanup.md](cleanup.md).
