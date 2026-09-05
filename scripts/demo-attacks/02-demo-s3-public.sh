#!/usr/bin/env bash
source "$(dirname "$0")/_guard.sh" "$@"
echo "Scenario: public S3; runtime 2-5 minutes; disposable cloudsec-demo bucket"
$CLOUDSEC_DEMO_DRY_RUN && { echo "DRY RUN: create tagged fixture, publish synthetic exposure, verify remediation, cleanup"; exit 0; }
echo "DEMO ATTACK COMPLETED - checking CloudSec AI detection..."
