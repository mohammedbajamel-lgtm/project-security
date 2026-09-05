#!/usr/bin/env bash
source "$(dirname "$0")/_guard.sh" "$@"
echo "Scenario: open SSH security group; runtime 2-5 minutes; no EC2 instance is launched by this safe wrapper"
$CLOUDSEC_DEMO_DRY_RUN && { echo "DRY RUN: use tagged demo SG fixture, publish synthetic finding, cleanup rule"; exit 0; }
echo "DEMO ATTACK COMPLETED - checking CloudSec AI detection..."
