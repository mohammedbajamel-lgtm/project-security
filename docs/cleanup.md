# Cleanup and destroy

> [!CAUTION]
> Cleanup permanently removes incidents, findings, reports, and lab resources. Back up required evidence first. Object Lock and KMS deletion cannot be completed immediately.

Run `scripts/cleanup-all.sh --environment lab --dry-run` first. The script refuses production, checks the caller account against tfvars, requires `--confirm`, and delegates dependency ordering to the reviewed Terraform graph.

Manual reverse order: stop new simulations/ingestion; stop Step Functions executions; remove EventBridge targets/rules then the custom bus; remove approval/API, functions and versions; remove alarms/logs; stop/delete CloudTrail; empty all permitted S3 object versions/delete markers; delete DynamoDB tables and wait for deletion; remove roles/policies; disable and schedule CMKs for the minimum approved window; then remove backend state only after everything else is verified.

Object-lock governance/compliance retention cannot simply be suspended for existing versions. Wait until retention expires unless authorized governance bypass is explicitly designed and approved. Never weaken retention merely to make a demo teardown faster.

Allow 15–45 minutes for ordinary resources, longer for large/versioned buckets, and at least the KMS pending-deletion window for final key removal. Verify with Resource Explorer/Tag Editor, service consoles, `terraform state list`, and a final refresh-only plan. Check Cost Explorer/Billing over the following 24–48 hours; delayed usage can still appear.
