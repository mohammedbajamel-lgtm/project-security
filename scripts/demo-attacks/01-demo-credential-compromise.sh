#!/usr/bin/env bash
source "$(dirname "$0")/_guard.sh" "$@"
echo "Scenario: credential compromise; runtime 2-5 minutes; disposable cloudsec-demo IAM fixture"
$CLOUDSEC_DEMO_DRY_RUN && { echo "DRY RUN: publish synthetic UnauthorizedAccess evidence and await isolated workflow"; exit 0; }
echo "Use the pre-created minimal demo user; publishing synthetic fixture (no credentials created here)."
echo "DEMO ATTACK COMPLETED - checking CloudSec AI detection..."
