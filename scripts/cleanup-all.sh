#!/usr/bin/env bash
set -euo pipefail

ENVIRONMENT=""; CONFIRM=false; DRY_RUN=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --environment) ENVIRONMENT="${2:-}"; shift 2 ;;
    --dry-run) DRY_RUN=true; shift ;;
    --confirm) CONFIRM=true; shift ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ "$ENVIRONMENT" =~ ^(dev|lab|demo)$ ]] || { echo "Refusing: --environment must be dev, lab, or demo" >&2; exit 2; }
TFVARS="terraform/environments/$ENVIRONMENT/$ENVIRONMENT.tfvars"
[[ -f "$TFVARS" ]] || { echo "Missing $TFVARS" >&2; exit 2; }
EXPECTED=$(sed -nE 's/^[[:space:]]*security_account_id[[:space:]]*=[[:space:]]*"([0-9]{12})".*/\1/p' "$TFVARS" | head -1)
ACTUAL=$(aws sts get-caller-identity --query Account --output text)
[[ -n "$EXPECTED" && "$ACTUAL" == "$EXPECTED" ]] || { echo "Refusing account mismatch: caller=$ACTUAL expected=$EXPECTED" >&2; exit 1; }
[[ "$ENVIRONMENT" != "prod" ]] || { echo "Production cleanup is prohibited" >&2; exit 1; }
export TF_DATA_DIR="${TF_DATA_DIR:-$PWD/terraform/.terraform-$ENVIRONMENT}"
terraform -chdir=terraform init -reconfigure -backend-config="environments/$ENVIRONMENT/backend.hcl"
terraform -chdir=terraform plan -destroy -var-file="environments/$ENVIRONMENT/$ENVIRONMENT.tfvars" -out="destroy-$ENVIRONMENT.binary"
terraform -chdir=terraform show -no-color "destroy-$ENVIRONMENT.binary"
if $DRY_RUN; then echo "DRY RUN ONLY: reviewed destroy plan saved; no resources changed"; exit 0; fi
$CONFIRM || { echo "Refusing: rerun with --confirm only after reviewing the plan" >&2; exit 2; }
terraform -chdir=terraform apply "destroy-$ENVIRONMENT.binary"
echo "Terraform cleanup finished. Review retained S3 objects and pending KMS deletions per docs/cleanup.md."
