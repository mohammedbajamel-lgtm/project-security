#!/usr/bin/env bash
set -euo pipefail

ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
EXPECTED_ACCOUNT="${CLOUDSEC_LAB_ACCOUNT_ID:?Set CLOUDSEC_LAB_ACCOUNT_ID to the intended lab account}"
if [[ "$ACCOUNT" != "$EXPECTED_ACCOUNT" ]]; then
  echo "Refusing unexpected account $ACCOUNT" >&2
  exit 1
fi

python lab/simulations/simulate_cloudtrail_tamper.py --lab --cleanup || true
bash lab/simulations/run_all_simulations.sh --cleanup

export TF_DATA_DIR="${TF_DATA_DIR:-.terraform-lab}"
terraform -chdir=terraform init -reconfigure -backend-config=environments/lab/backend.hcl
terraform -chdir=terraform destroy -var-file=environments/lab/lab.tfvars
