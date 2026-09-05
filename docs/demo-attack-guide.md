# Safe demo attack guide

All scripts require `CLOUDSEC_ENVIRONMENT=demo`, the dedicated `CLOUDSEC_DEMO_ACCOUNT_ID`, `--demo-only`, and either `--dry-run` or `--confirm-live`. They refuse account mismatch. Start with `run-all-demo.sh --demo-only --dry-run --delay 1`.

| Scenario | Expected signal | Detection/lifecycle target | Rollback |
|---|---|---|---|
| Credential compromise | synthetic unauthorized access | incident <5 min; approval path | keep fixture key active/recreate only from IaC |
| Public S3 | tagged fixture exposure | incident <5 min; block public access | Terraform restores fixture |
| Security group | tagged SSH ingress | incident <5 min; revoke rule | delete only exact demo rule |
| CloudTrail tamper | synthetic StopLogging evidence | incident <5 min; safe validation | trail is never actually stopped |

The wrappers favor synthetic evidence over risky behavior. If detection does not appear, stop; inspect EventBridge, Lambda logs, DLQ, and DynamoDB before retrying. Never substitute a production account or broader policy.
