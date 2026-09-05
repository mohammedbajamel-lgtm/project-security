#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$ROOT/../.." && pwd)"
if [[ -x "$PROJECT_ROOT/.venv/Scripts/python.exe" ]]; then
  PYTHON="$PROJECT_ROOT/.venv/Scripts/python.exe"
  SCRIPT_ROOT="$(wslpath -w "$ROOT")"
else
  PYTHON="${PYTHON:-python3}"
  SCRIPT_ROOT="$ROOT"
fi
MODE="${1:---dry-run}"
if [[ "$MODE" != "--dry-run" && "$MODE" != "--confirm" && "$MODE" != "--cleanup" ]]; then
  echo "Usage: $0 --dry-run|--confirm|--cleanup" >&2
  exit 2
fi

scripts=(
  simulate_compromised_iam_key.py
  simulate_sg_change.py
  simulate_public_s3.py
  simulate_ec2_compromise.py
  simulate_cloudtrail_tamper.py
  simulate_privilege_escalation.py
)

for script in "${scripts[@]}"; do
  if [[ "$MODE" == "--dry-run" ]]; then
    "$PYTHON" "$SCRIPT_ROOT/$script" --lab --dry-run
  elif [[ "$MODE" == "--cleanup" ]]; then
    "$PYTHON" "$SCRIPT_ROOT/$script" --lab --cleanup
  else
    "$PYTHON" "$SCRIPT_ROOT/$script" --lab
    sleep 120
  fi
done

if [[ "$MODE" == "--confirm" ]]; then
  "$PYTHON" "$SCRIPT_ROOT/publish_practice_findings.py" --lab
  "$PYTHON" "$SCRIPT_ROOT/validate_simulations.py" --lab
fi
