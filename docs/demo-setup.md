# Demo setup

Prerequisites: a dedicated demo AWS account, AWS CLI/SSO, Terraform, Python 3.11, Git, a demo backend, and a confirmed budget alert. Setup typically takes 15–20 minutes. Allow a conservative $10 ceiling for a four-hour session and verify current pricing.

1. Copy the demo `.example` files, insert only the dedicated demo account ID, and keep them untracked.
2. Export `CLOUDSEC_ENVIRONMENT=demo` and `CLOUDSEC_DEMO_ACCOUNT_ID=<id>`.
3. Preview: `bash scripts/setup-demo.sh --account <id> --region us-east-1 --duration-hours 4 --no-real-data --dry-run`.
4. Review the plan, then rerun with `--confirm`. The mandatory `--no-real-data` flag prevents normal telemetry from being treated as demo input.
5. Seed synthetic fixtures only: three active incidents, two pending approval records, and one completed remediation/evidence bundle. Use twelve JSON fixtures from the test scenario catalogue; never copy production findings.
6. Create a Cognito demo user manually through the approved identity workflow, require a password reset/MFA, and delete it during teardown. Do not put passwords in scripts.
7. Teardown: rerun with `--teardown --confirm`, then follow [cleanup](cleanup.md) for retained objects and KMS keys.

The setup helper intentionally does not manufacture credentials or silently create identity users. Those actions require an authenticated, reviewed operator step.
