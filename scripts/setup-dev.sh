#!/usr/bin/env bash
# CloudSec AI — Dev Environment Setup Script
# Usage: bash scripts/setup-dev.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON_BIN="${PYTHON_BIN:-python3.11}"
PYTHON_MIN="3.11"
TERRAFORM_MIN="1.6"

echo "===== CloudSec AI Dev Setup ====="

# ---- Python ----
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "ERROR: $PYTHON_BIN not found. Install Python $PYTHON_MIN+ and set PYTHON_BIN."
  exit 1
fi

PY_VER="$($PYTHON_BIN - <<'PYEOF'
import sys
print(f"{sys.version_info.major}.{sys.version_info.minor}")
PYEOF
)"
echo "Python version: $PY_VER"

# Basic version check
PY_MAJOR="${PY_VER%%.*}"
PY_MINOR="${PY_VER#*.}"
if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 11 ]; }; then
  echo "ERROR: Python $PYTHON_MIN+ required (found $PY_VER)"
  exit 1
fi

# ---- Virtualenv ----
if [ ! -d ".venv" ]; then
  echo "Creating virtual environment .venv ..."
  "$PYTHON_BIN" -m venv .venv
fi
source .venv/bin/activate
echo "Activated .venv ($(which python))"

# ---- Dependencies ----
echo "Installing runtime + dev dependencies ..."
python -m pip install --upgrade pip >/dev/null 2>&1
python -m pip install -e '.[dev,security]' >/dev/null 2>&1 || {
  # Fallback: direct pip install of the pyproject optional groups
  python -m pip install \
    "boto3>=1.34.0,<2.0" \
    "botocore>=1.34.0,<2.0" \
    "jinja2>=3.1.0,<4.0" \
    "requests>=2.31.0,<3.0" \
    "pydantic>=2.5.0,<3.0" \
    "jsonschema>=4.21.0,<5.0" \
    "pytest>=8.0.0,<9.0" \
    "pytest-cov>=5.0.0,<6.0" \
    "pytest-mock>=3.12.0,<4.0" \
    "moto[s3,sqs,sns,lambda,dynamodb,kms,iam,cloudtrail,events,ssm]>=5.0.0,<6.0" \
    "black>=24.1.0,<25.0" \
    "ruff>=0.4.0,<0.5.0" \
    "mypy>=1.9.0,<2.0" \
    "bandit>=1.7.5,<2.0" \
    "safety>=3.0.0,<4.0" \
    "freezegun>=1.5.0,<2.0"
}

# ---- Verification ----
echo ""
echo "===== Verification ====="
python -c "import boto3, pytest, jsonschema; print('boto3 / pytest / jsonschema: OK')"
python -m pytest --version | head -1
terraform --version | head -1
if [ $? -ne 0 ]; then
  echo "WARNING: terraform not on PATH. Install Terraform >= $TERRAFORM_MIN."
else
  TF_VER="$(terraform --version | awk '{print $2}' | sed 's/v//')"
  echo "Terraform: $TF_VER"
fi

echo ""
echo "===== Setup complete ====="
echo "To start developing:"
echo "  source .venv/bin/activate"
echo "  cd terraform && terraform init -backend-config=environments/dev/backend.hcl"
echo "  pytest tests/unit"
