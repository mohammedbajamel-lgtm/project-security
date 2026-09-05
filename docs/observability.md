# CloudSec AI Observability

The Phase 17 dashboards use a default 24-hour time range:

- `cloudsec-dev-overview` — telemetry, incidents, AI, remediation, Lambda, Step Functions, and DynamoDB health.
- `cloudsec-dev-cost` — estimated AWS charges with links to Cost Explorer and Budgets.
- `cloudsec-dev-security` — escalations, high-severity findings, and anomaly scores.

Open them in CloudWatch **Dashboards** in `us-east-1`. All alarms publish to the encrypted `cloudsec-dev-errors` SNS topic. Development Lambda log groups retain data for 30 days; production uses 365 days.
