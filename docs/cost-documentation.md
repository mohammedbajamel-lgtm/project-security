# Cost documentation

Estimates are planning ranges, not quotes; region, volume, retention, model, and current AWS pricing determine actual charges. Confirm with AWS Pricing Calculator before deployment.

| Service | Dev/month | Production/month | Driver |
|---|---:|---:|---|
| Bedrock | $10–35 | $75–300 | input/output tokens and investigations |
| CloudTrail/S3 | $5–20 | $40–150 | events, copies, storage and retention |
| DynamoDB | $2–10 | $20–100 | reads/writes/storage/backups |
| KMS | $4–10 | $10–30 | CMKs and requests |
| Lambda/Step Functions/EventBridge | $1–10 | $10–75 | invocations, duration, transitions/events |
| CloudWatch/SNS/SQS/API | $3–15 | $20–100 | logs, metrics, alarms, requests |
| **Planning total** | **$25–100** | **$175–755** | workload dependent |

For Bedrock, estimate daily investigations × average input tokens × input rate plus output tokens × output rate. Track both token counts. A small incident lifecycle may cost cents; evidence-heavy model calls can dominate. Do not claim a fixed per-incident cost until measured.

Top drivers are Bedrock, CloudTrail/S3 retention, and DynamoDB at volume. Prefer a smaller capable model (for example Haiku rather than Sonnet) after quality evaluation, compute baselines less often in quiet accounts, archive old findings, shorten non-regulatory log retention, and batch safe operations. Savings Plans generally apply to eligible compute, not Bedrock inference; verify current AWS terms before relying on them.

Recommended starting budgets are $50/month for dev/lab and a workload-derived production budget (often $500 as an initial ceiling), with alerts at 80%, 100%, and 120%. Configure budgets before infrastructure and add anomaly detection. Review actual cost per incident after every test cycle.
