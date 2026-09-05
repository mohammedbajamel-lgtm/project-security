# CloudSec Phase 18 Lab Operations

> **SIMULATION — NOT A REAL ATTACK. Never run these commands in production.**

## Architecture and isolation

```text
Dedicated lab account or approved isolated shared account
  cloudsec-lab state (separate S3 key)
    isolated VPC 10.250.0.0/16
      private subnet; no internet gateway, NAT, peering, or transit gateway
    dedicated CloudTrail -> dedicated encrypted/private S3 bucket
    GuardDuty + Security Hub
    restricted lab operator + permissions boundary
    cloudsec-lab-* simulation resources only
```

All lab resources carry `Environment=lab` and `Isolation=strict`. The operator cannot assume roles, create credentials, change trust policies, use AWS Organizations, create peering, or create Transit Gateway attachments. This shared-account design intentionally replaces the task's account-wide AdministratorAccess user with a bounded operator.

## Deploy

Use a separate Terraform data directory so the dev backend selection is not changed:

```bash
export TF_DATA_DIR=.terraform-lab
terraform -chdir=terraform init -reconfigure -backend-config=environments/lab/backend.hcl
terraform -chdir=terraform plan -var-file=environments/lab/lab.tfvars -out=tfplan-phase18.binary
terraform -chdir=terraform apply tfplan-phase18.binary
python scripts/verify-phase18.py
```

Review the saved plan before applying. Expected ongoing lab cost is approximately $5–30/month depending on telemetry and simulation duration. EC2 simulations add short-lived usage.

## Run simulations

Always inspect the dry run first:

```bash
bash lab/simulations/run_all_simulations.sh --dry-run
```

Run one scenario with `python lab/simulations/<script>.py --lab`. Run all six only after approval:

```bash
bash lab/simulations/run_all_simulations.sh --confirm
```

The orchestrator waits two minutes between scenarios and then checks CloudTrail evidence for all six incident types. Individual scripts print their generated resource identifiers. Findings can be checked in GuardDuty, Security Hub, and the `cloudsec-lab-findings` DynamoDB table.

## Cleanup

Clean only simulation resources:

```bash
bash lab/simulations/run_all_simulations.sh --cleanup
```

Destroy the whole lab:

```bash
bash scripts/cleanup-lab.sh
```

## Emergency cleanup (target: under five minutes)

Start the lab trail, run simulation cleanup, terminate resources tagged `Environment=lab`, and run the Terraform destroy command above. Never delete or modify a resource that does not start with `cloudsec-lab-` or lack both lab isolation tags.

## Troubleshooting

- `Refusing to run without --lab`: add the mandatory confirmation flag.
- Unexpected account: stop; do not bypass the account guard.
- Public ACL blocked: expected when account-level S3 Block Public Access is enabled; the attempted API call still provides detection evidence.
- No finding yet: GuardDuty/Security Hub can take several minutes; use CloudTrail event IDs as immediate evidence.
- Cleanup reports dependency violations: terminate lab EC2 instances before deleting security groups or the VPC.
