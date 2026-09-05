# Troubleshooting

Never fix an error by granting broad IAM access, disabling a detector, bypassing approval, or weakening evidence retention. Capture UTC time, request/execution ID, environment, commit and redacted logs first.

## Terraform deployment

| Symptom / likely cause | Diagnose | Fix and prevention |
|---|---|---|
| `no existing key found` / KMS foundation absent | `terraform -chdir=terraform state list` and `aws kms list-aliases` | deploy Phase 1 KMS first; keep dependency order |
| lock timeout / interrupted run | inspect the backend lock and confirm no active operator | use `terraform force-unlock <lock-id>` only after proving it is stale; serialize deployments |
| assumed role has no access / SSO mismatch | `aws sts get-caller-identity`; `aws configure list-profiles` | log into the intended SSO profile and correct T01-03 trust; do not add admin access |

## Detection and ingestion

For missing GuardDuty findings, inspect the enabled detector, EventBridge rule/targets, ingestion Lambda logs, DLQ, and finding-table key. For CloudTrail parsing, check trail status, delivery bucket notification, object format and parser logs. For Security Hub drops, confirm enablement and region coverage.

```bash
aws events list-targets-by-rule --event-bus-name cloudsec-<env>-security-bus --rule <rule>
aws logs tail /aws/lambda/cloudsec-<env>-guardduty-ingestor --since 30m
aws sqs get-queue-attributes --queue-url <url> --attribute-names ApproximateNumberOfMessages
aws cloudtrail get-trail-status --name cloudsec-<env>-trail
```

Fix the exact rule, permission, schema, or supported log format in Terraform/code, then add a regression test. Never disable the source.

## Correlation

Uncorrelated findings usually indicate a time-window, ARN normalization, partition-key or source-IP mismatch. Duplicates indicate an unstable idempotency key or non-conditional write. Query the incident/finding IDs, compare normalized fields and inspect correlation logs; correct deterministic keys rather than deleting evidence.

## Bedrock investigation

For timeout, confirm regional model access, quotas, latency metrics, and bounded retry logs. For malformed reports, save the redacted response and validate it against the investigation schema. For hallucinated entities, inspect citation/evidence validator output. Fix model selection/prompt/schema handling; never skip validation.

```bash
aws bedrock list-foundation-models --region <region>
aws logs tail /aws/lambda/cloudsec-<env>-investigation --since 30m
```

## Safety, approval, remediation and verification

If an approved action does not execute, inspect the decision, EventBridge target/DLQ, Step Functions history, and exact invocation role. If approval is absent, inspect Cognito authentication, API Gateway access logs, handler logs, expiry, and SNS subscription. If verification fails, allow eventual consistency, inspect the read-only verification call, and escalate—do not force `RESOLVED`.

```bash
aws stepfunctions list-executions --state-machine-arn <arn> --max-results 10
aws stepfunctions get-execution-history --execution-arn <arn>
aws logs tail /aws/lambda/cloudsec-<env>-approval-handler --since 30m
aws logs tail /aws/lambda/cloudsec-<env>-verification-engine --since 30m
```

## Evidence, reporting and observability

Missing evidence usually means bucket-policy, KMS grant, retention or prefix mismatch. Missing reports point to reporting logs, templates, KMS/S3 writes or SNS policy. For silent alarms, inspect metric namespace/dimensions, period, threshold and missing-data treatment. For a stuck DLQ, preserve a sample, identify the original failure, repair it, and redrive through an approved process.

```bash
aws s3api head-object --bucket <evidence-bucket> --key <key>
aws kms describe-key --key-id <key-arn>
aws cloudwatch describe-alarms --alarm-name-prefix cloudsec-<env>
```

## Escalation and known issues

Escalate from self-service runbook → development owner → platform/security team → AWS Support, carrying redacted evidence and request IDs. Current known constraints: nighttime rules can elevate nominal Level 1 tests to Level 2; eventual consistency can delay verification; model access varies by region; object retention and KMS deletion delay cleanup; Terraform plans expire when state changes. Work with these controls—do not bypass them.
