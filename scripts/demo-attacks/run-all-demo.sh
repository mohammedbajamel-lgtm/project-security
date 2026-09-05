#!/usr/bin/env bash
set -euo pipefail
DELAY=10
ARGS=("$@")
for ((i=1;i<=$#;i++)); do [[ "${!i}" == "--delay" ]] && { j=$((i+1)); DELAY="${!j}"; }; done
for script in 01-demo-credential-compromise.sh 02-demo-s3-public.sh 03-demo-security-group.sh 04-demo-cloudtrail-tamper.sh; do
  bash "$(dirname "$0")/$script" "${ARGS[@]}"
  sleep "$DELAY"
done
