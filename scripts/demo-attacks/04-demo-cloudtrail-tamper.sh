#!/usr/bin/env bash
source "$(dirname "$0")/_guard.sh" "$@"
echo "Scenario: CloudTrail tamper; runtime 2-5 minutes; synthetic event only—the audit trail is never stopped"
$CLOUDSEC_DEMO_DRY_RUN && { echo "DRY RUN: publish synthetic StopLogging finding and verify safe response"; exit 0; }
echo "DEMO ATTACK COMPLETED - checking CloudSec AI detection..."
