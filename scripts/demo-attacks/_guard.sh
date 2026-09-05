#!/usr/bin/env bash
set -euo pipefail
[[ " ${*} " == *" --demo-only "* ]] || { echo "Refusing: --demo-only is mandatory" >&2; exit 2; }
[[ -n "${CLOUDSEC_DEMO_ACCOUNT_ID:-}" ]] || { echo "Set CLOUDSEC_DEMO_ACCOUNT_ID" >&2; exit 2; }
ACTUAL=$(aws sts get-caller-identity --query Account --output text)
[[ "$ACTUAL" == "$CLOUDSEC_DEMO_ACCOUNT_ID" ]] || { echo "Refusing account mismatch" >&2; exit 1; }
[[ "${CLOUDSEC_ENVIRONMENT:-}" == "demo" ]] || { echo "Refusing: CLOUDSEC_ENVIRONMENT must equal demo" >&2; exit 1; }
if [[ " ${*} " == *" --dry-run "* ]]; then export CLOUDSEC_DEMO_DRY_RUN=true; else
  [[ " ${*} " == *" --confirm-live "* ]] || { echo "Refusing: --confirm-live is required" >&2; exit 2; }
  export CLOUDSEC_DEMO_DRY_RUN=false
fi
