# Verified Evidence Gallery

This gallery documents the isolated CloudSec AI lab deployment. Public screenshots are deliberately sanitized: AWS account identifiers, resource IDs, live endpoints, local filesystem paths, and private originals are not included.

## Build quality and infrastructure state

| Automated tests | Terraform reconciliation |
|---|---|
| ![171 tests passed with coverage above the required threshold](screenshots/tests-passed.png) | ![Terraform reports no infrastructure drift](screenshots/terraform-no-changes.png) |

## Ingestion and incident correlation

![Normalized findings stored in DynamoDB](screenshots/dynamodb-findings-overview.png)

![Public S3 finding normalized into the findings store](screenshots/dynamodb-public-s3-finding.png)

![Multiple findings correlated into one incident](screenshots/correlated-incident.png)

## Event-driven control plane

| Core lifecycle rules | Terminal outcome rules |
|---|---|
| ![Enabled EventBridge ingestion and investigation rules](screenshots/eventbridge-rules-core.png) | ![Enabled EventBridge remediation and reporting rules](screenshots/eventbridge-rules-outcomes.png) |

| Lambda functions—part 1 | Lambda functions—part 2 |
|---|---|
| ![CloudSec Lambda functions](screenshots/lambda-functions-top.png) | ![Additional CloudSec Lambda functions](screenshots/lambda-functions-bottom.png) |

## Approval and remediation

![Successful policy-controlled Step Functions workflow](screenshots/stepfunctions-workflow-success.png)

![Approval API resource structure](screenshots/api-gateway-approval-resources.png)

![Redacted Cognito approval user pool](screenshots/cognito-user-pool-redacted.png)

## Evidence preservation

![Isolated end-to-end evidence prefixes](screenshots/s3-evidence-prefixes.png)

![Complete incident evidence package](screenshots/s3-evidence-package.png)

The evidence package contains blast-radius analysis, an investigation report, manifest, remediation history, generated reports, and independent verification results.

## Access control and encryption

![Scoped CloudSec lab IAM roles](screenshots/iam-lab-roles-redacted.png)

| Role policy | Selected least-privilege controls |
|---|---|
| ![Custom remediation policy](screenshots/iam-remediation-permissions.png) | ![S3 containment actions](screenshots/iam-remediation-policy-containment.png) |

![Separated KMS keys for evidence, incidents, SSM, and findings](screenshots/kms-lab-keys.png)

## Observability and resilience

| Remediation outcomes | Platform health |
|---|---|
| ![Remediation and verification metrics](screenshots/cloudwatch-remediation.png) | ![Step Functions and DynamoDB health](screenshots/cloudwatch-system-health.png) |

![Security dashboard](screenshots/cloudwatch-security.png)

![Encrypted SQS dead-letter queue policy](screenshots/sqs-dlq-encryption-policy.png)

![DLQ monitoring after an intentional malformed-event test](screenshots/sqs-dlq-monitoring.png)

![SNS notification topics](screenshots/sns-notification-topics.png)

## Audit and governance

| CloudTrail status | Resource governance tags |
|---|---|
| ![CloudTrail logging active](screenshots/cloudtrail-logging-status.png) | ![Terraform-managed strict lab isolation tags](screenshots/cloudtrail-governance-tags.png) |

## Cost controls

| Current budget health | Alert thresholds |
|---|---|
| ![Healthy monthly lab budget](screenshots/budget-health.png) | ![Budget alerts at 80, 100, and 120 percent](screenshots/budget-alerts.png) |

![CloudWatch estimated-charge dashboard](screenshots/cloudwatch-cost.png)

## Interpretation notes

- Empty decision tables after testing are expected because the end-to-end runner removes temporary approval records during cleanup.
- A visible DLQ message is intentional evidence from the malformed-event failure-path checkpoint.
- Some metrics appear only during the short live-test window; zero or empty panels do not imply that the corresponding control is absent.
- The lab is single-region and deliberately isolated. Production deployment requires an additional security, availability, and governance review.
