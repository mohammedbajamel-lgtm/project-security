# Phase 4–5 deployment and review

This deployment adds the correlation engine, three Standard-tier SSM parameters, a KMS-encrypted on-demand baselines table, a daily baseline Lambda, and one CloudWatch alarm. It does not enable Bedrock or remediation. Expected dev cost is low and usage-based; CloudTrail LookupEvents and DynamoDB requests are the main drivers.

The account concurrency quota is currently 10, all of it unreserved. Therefore dev uses unreserved concurrency (`-1`) for the baseline Lambda. Set `baseline_reserved_concurrency = 2` only after raising the account concurrency quota to at least 12.

The scheduled Lambda timeout is five minutes because collecting 30 days of paginated account-level CloudTrail history can exceed 30 seconds. Per-principal computation remains bounded and is tested independently.

Each daily run samples at most 5,000 management events from the requested 30-day window. This prevents high-volume accounts from timing out or monopolizing the CloudTrail LookupEvents quota. If the sample spans less than seven days, the resulting confidence stays below 0.5 and anomaly scoring fails safely as insufficient data.

## Review and apply

From the repository root:

```powershell
terraform -chdir="terraform" show -no-color "tfplan-phase45.binary"
terraform -chdir="terraform" apply "tfplan-phase45.binary"
powershell -ExecutionPolicy Bypass -File "scripts\verify-phase45.ps1"
```

Never apply a plan after changing source files; regenerate and review it first.

## Phase 5 checkpoint

The verifier confirms the resources and settings. Then invoke `cloudsec-dev-baseline-computation` for a principal that has CloudTrail management activity. Confirm a record exists in `cloudsec-dev-baselines`, compare a normal and unusual finding with the unit-test examples, and confirm the table size is reasonable. Phase 6 must not begin until this manual review is accepted.
