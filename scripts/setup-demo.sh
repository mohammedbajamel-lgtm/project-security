#!/usr/bin/env bash
set -euo pipefail

ACCOUNT=""; REGION="us-east-1"; HOURS=4; NO_REAL_DATA=false; DRY_RUN=false; CONFIRM=false; TEARDOWN=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --account) ACCOUNT="${2:-}"; shift 2;; --region) REGION="${2:-}"; shift 2;;
    --duration-hours) HOURS="${2:-}"; shift 2;; --no-real-data) NO_REAL_DATA=true; shift;;
    --dry-run) DRY_RUN=true; shift;; --confirm) CONFIRM=true; shift;; --teardown) TEARDOWN=true; shift;;
    *) echo "Unknown argument: $1" >&2; exit 2;;
  esac
done
[[ "$ACCOUNT" =~ ^[0-9]{12}$ ]] || { echo "--account requires a 12-digit dedicated demo account" >&2; exit 2; }
$NO_REAL_DATA || { echo "Refusing: --no-real-data is mandatory" >&2; exit 2; }
[[ "$HOURS" =~ ^[0-9]+$ && "$HOURS" -ge 1 && "$HOURS" -le 24 ]] || { echo "--duration-hours must be 1-24" >&2; exit 2; }
ACTUAL=$(aws sts get-caller-identity --query Account --output text)
[[ "$ACTUAL" == "$ACCOUNT" ]] || { echo "Refusing account mismatch: caller=$ACTUAL requested=$ACCOUNT" >&2; exit 1; }
[[ -f terraform/environments/demo/demo.tfvars ]] || { echo "Create demo.tfvars from demo.tfvars.example first" >&2; exit 2; }
grep -Eq '^[[:space:]]*environment[[:space:]]*=[[:space:]]*"demo"' terraform/environments/demo/demo.tfvars || { echo "Refusing non-demo tfvars" >&2; exit 1; }
export TF_DATA_DIR="${TF_DATA_DIR:-$PWD/terraform/.terraform-demo}"
if $TEARDOWN; then exec bash scripts/cleanup-all.sh --environment demo $($DRY_RUN && echo --dry-run) $($CONFIRM && echo --confirm); fi
terraform -chdir=terraform init -reconfigure -backend-config=environments/demo/backend.hcl
terraform -chdir=terraform plan -var-file=environments/demo/demo.tfvars -out=tfplan-demo.binary
terraform -chdir=terraform show -no-color tfplan-demo.binary
if $DRY_RUN; then echo "DRY RUN ONLY: no resources changed"; exit 0; fi
$CONFIRM || { echo "Refusing: review plan and rerun with --confirm" >&2; exit 2; }
terraform -chdir=terraform apply tfplan-demo.binary
echo "Demo deployed for at most $HOURS hour(s) in $REGION. Real telemetry remains disabled."
echo "Seed only synthetic fixtures documented in docs/demo-setup.md, then schedule teardown."
