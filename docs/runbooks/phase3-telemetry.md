# Phase 3 telemetry deployment and checkpoint

GuardDuty, Security Hub, and AWS Config default-bus events are routed to dedicated ingestion Lambdas. Each handler validates and normalizes untrusted input, writes the findings table, emits `FindingIngested` on the custom security bus, and sends failures to the encrypted DLQ.

## Safe defaults

The organization CloudTrail, Config aggregator, and Security Lake modules are disabled in dev. They require explicit variables because they incur recurring charges and require AWS Organizations permissions. CloudTrail Object Lock is a separate opt-in; COMPLIANCE retention cannot be shortened or bypassed.

The dev account currently cannot reserve Lambda concurrency without violating AWS's minimum of 10 unreserved executions. `telemetry_reserved_concurrency = -1` therefore uses unreserved concurrency. Set it to `5` only after the account concurrent-execution quota is at least 25 plus any other reserved concurrency.

Enable only after confirming management-account or delegated-administrator status:

```hcl
enable_organization_cloudtrail          = true
enable_cloudtrail_object_lock           = true
cloudtrail_object_lock_retention_days   = 30
enable_config_aggregator                = true
enable_organization_config_aggregation = true
config_organization_role_arn            = "arn:aws:iam::<account>:role/<config-role>"
enable_security_lake                    = true
security_lake_meta_store_manager_role_arn = "arn:aws:iam::<account>:role/<security-lake-role>"
telemetry_account_ids                   = ["<workload-account>"]
telemetry_regions                       = ["us-east-1"]
```

Expected service costs vary with telemetry volume: GuardDuty and Security Hub commonly add several dollars per account monthly; CloudTrail, Config, and Security Lake can add tens of dollars monthly. Athena queries add scanned-data charges.

## Mandatory checkpoint

After an approved apply, run `scripts/verify-phase3.ps1`. Then publish a safe synthetic GuardDuty-shaped event or generate a GuardDuty sample finding. Confirm one normalized item in `cloudsec-dev-findings`, one `FindingIngested` delivery, and one deliberately malformed test event in `cloudsec-dev-dlq`. Do not proceed to Phase 4 until these checks pass.

DLQ messages are consumed only by the recovery role. Inspect and redrive after correcting the cause; never discard evidence without review.
