# CloudSec AI — Cost Controls

## Budgets

| Environment | Monthly limit | Alert thresholds |
|-------------|---------------|------------------|
| dev         | $50           | 80% / 100% / 120% |
| staging     | $200          | 80% / 100% / 120% |
| prod        | $500          | 80% / 100% / 120% |

Budgets are created as `AWS Budgets` resources filtered on the tags
`Project=cloudsec-ai` and `Environment=<env>`. Notifications are delivered
via SNS to the topic `cloudsec-{env}-cost-alerts`.

## Anomaly Detection

AWS Cost Anomaly Detection should be enabled on the Security Account for
cost anomalies matching the CloudSec AI tag scope. This is enabled in the
account-level Cost Management console and can be driven by an SSM
automation document when needed.

## Cost Allocation Tags

All resources carry these mandatory tags, which the AWS Cost Explorer uses
for cost allocation:

| Tag | Purpose |
|-----|---------|
| `Project` | Top-level grouping |
| `Environment` | dev/staging/prod isolation |
| `ManagedBy` | IaC vs manual |
| `CostCenter` | Business cost owner |
| `CreatedBy` | Responsible team |

## Monitoring

- AWS Budget console → Budget `cloudsec-{env}-monthly-budget`
- Cost Explorer → filter `Project=cloudsec-ai AND Environment=<env>`
- CloudWatch → budget utilization alarms via SNS fanout

## Responsibility

The platform team owns the budget thresholds. If a budget alert fires, the
on-call security engineer must investigate the root-cause cost driver and
either scale down the responsible resource or update the budget.
