# Implementation Plan: CloudSec AI

## Overview

CloudSec AI is a 20-phase implementation plan for building an AWS-native automated incident response platform. The platform ingests security telemetry from GuardDuty, Security Hub, CloudTrail, VPC Flow Logs, and AWS Config; correlates findings into incidents; uses Amazon Bedrock for AI-driven investigation; executes approved remediation playbooks through a deterministic safety-validation layer; verifies remediation success; and generates forensic reports.

The implementation follows a strict sequential dependency chain — each phase builds on the outputs of prior phases. Six manual review checkpoints are placed at Phase 2, 3, 5, 9, 13, and 19 to validate correctness before proceeding. Two implementation tracks are defined: the MVP Track covers one complete attack lifecycle (Compromised IAM Credential) using GuardDuty + CloudTrail in a single account; the Full Platform Track covers all six remediation scenarios across all telemetry sources and multi-account deployment.

Six danger flag categories are used throughout: CHARGES (AWS charges), HARD-TO-DELETE (persistent resources), IAM-CHANGE (IAM modifications), AUTO-REMEDIATION (enables automated fixes), HUMAN-APPROVAL (requires approval), and SECURITY-RISK (incorrect implementation could create vulnerabilities).

## Task Dependency Graph

`mermaid
flowchart TD
    P1[Phase 1: Foundation] --> P2[Phase 2: Core Incident Platform]
    P2 --> P3[Phase 3: Security Telemetry]
    P3 --> P4[Phase 4: Correlation Engine]
    P4 --> P5[Phase 5: Behavior Baseline]
    P5 --> P6[Phase 6: AI Investigation Engine]
    P6 --> P7[Phase 7: Attack Reconstruction]
    P6 --> P8[Phase 8: Blast Radius]
    P7 --> P9[Phase 9: Safety Validation Engine]
    P8 --> P9
    P9 --> P10[Phase 10: Remediation Framework]
    P10 --> P11[Phase 11: Remediation Playbooks]
    P11 --> P12[Phase 12: Human Approval]
    P12 --> P13[Phase 13: Verification Engine]
    P13 --> P14[Phase 14: Evidence Preservation]
    P13 --> P15[Phase 15: Incident Reporting]
    P15 --> P16[Phase 16: Knowledge Base]
    P17[Phase 17: Observability] --> P18[Phase 18: Safe Attack Simulations]
    P14 --> P17
    P18 --> P19[Phase 19: End-to-End Testing]
    P19 --> P20[Phase 20: Portfolio and Demo]
    P6 -.->|depends| P4
    P9 -.->|depends| P7
    P11 -.->|depends| P10
    P12 -.->|depends| P9
    P13 -.->|depends| P11
    P15 -.->|depends| P13
    P16 -.->|depends| P15
`

## Tasks

---

## Phase 1: Foundation

**Goal:** Establish the infrastructure foundation — repository, Terraform backend, provider configuration, naming standards, KMS, IAM foundations, and cost controls — before any application logic is deployed.

**Danger Flags in this phase:** 🟡[CHARGES] (S3 bucket, DynamoDB table), 🔴[HARD-TO-DELETE] (KMS keys), 🟠[IAM-CHANGE] (role/policy creation), 🟡[CHARGES] (cost controls)

### Task T01-01: Establish Repository Structure and CI/CD Skeleton

**Objective:** Create the monorepo layout with Terraform modules, Lambda source directories, test suites, and CI pipeline configuration.

**Files/Components Affected:** 	erraform/, lambda/, 	ests/, docs/, .github/workflows/, .terraform-version, .python-version, README.md

**AWS Services Involved:** None (local-only)

**Requirements Satisfied:** R2 (lifecycle foundation), R17 (observability foundation)

**Dependencies:** None

**Security Considerations:** Ensure .gitignore excludes .terraform/, *.tfstate, secrets, and .env files. Repository must use branch protection requiring PR review.

**Acceptance Criteria:**
1. Repository has directories: 	erraform/modules/, 	erraform/environments/, lambda/{correlation-engine,investigation-engine,safety-validation,verification-engine,reporting}, 	ests/unit/, 	ests/integration/, 	ests/e2e/, docs/
2. .github/workflows/ci.yml exists with lint, unit-test, and tfsec stages
3. .gitignore excludes Terraform state, credentials, and build artifacts
4. 	erraform.tfvars.example exists for each environment with placeholder values
5. Branch protection rules documented in README

**Tests Required:** None (structural)

**Expected Cost Impact:** 

**Manual Verification:** Clone repo and confirm all directories exist; confirm .gitignore blocks state files; confirm CI workflow is valid YAML

---

### Task T01-02: Configure Terraform Backend and State Locking

**Status:** COMPLETE (Stage 1 applied 2026-09-03 in the authorized AWS account, us-east-1; 6 resources created; all post-apply verifications passed; state lock mechanism tested)

**Stage 1 Apply Record:**
- Bucket: redacted from the public repository
- ARN: redacted from the public repository
- Plan result: 6 added, 0 changed, 0 destroyed
- Post-apply verification: bucket exists, versioning Enabled, default SSE AES256, all four Block Public Access flags true, bucket policy has exactly 2 Deny statements (DenyInsecureTransport + DenyUnencryptedUploads) with no Allow statements, 5 expected tags present, 0 unexpected objects, exactly one `cloudsec-dev-*` bucket in account
- State lock test: backend init succeeds; two `terraform plan` calls acquired and released locks; `.tflock` objects cleaned up after each plan
- Bootstrap local state preserved at `terraform/backend/terraform.tfstate` with backup at `terraform/backend/state-backups/terraform.tfstate.LATEST.backup` and `terraform/backend/state-backups/terraform.tfstate.<timestamp>.backup`
- Dev backend config written to `terraform/environments/dev/backend.hcl`
- Dev example tfvars written to `terraform/environments/dev/dev.tfvars.example`
- Stage 2 (bucket-policy Allow + DenyStateObjectDeletion) remains pending T01-07

**Objective:** Deploy a centralized Terraform backend using an S3 bucket with local-provider-lock-file state locking in the Security Account.

**Files/Components Affected:** terraform/backend/ (S3 bucket, bucket policy, encryption, versioning; NO DynamoDB)

**AWS Services Involved:** S3 only (Stage 1). IAM (T01-07) is needed for Stage 2 policy update.

**Design Decisions (per user review):**
- **TWO-STAGE BOOTSTRAP** resolves the T01-02 ↔ T01-07 dependency cycle. Stage 1 (T01-02) creates the bucket with versioning, SSE-S3, block-public-access, `force_destroy = false`, and ONLY security `Deny` statements (insecure-transport, unencrypted-uploads). No role-scoped `Allow` statements in Stage 1 — the deploy role does not yet exist. Stage 2 (post-T01-07) is a SEPARATE reviewed plan that adds the role-scoped `Allow` statements + `DenyStateObjectDeletion` once the real role is provisioned. No placeholder or nonexistent role ARN is ever written into a bucket policy.
- **DynamoDB lock table REMOVED.** State locking uses the S3 backend's `use_lockfile = true` setting (Terraform v1.6+), which writes a transient `.tflock` object at `<state_key>.tflock` alongside the state file. No backward-compatibility need.
- **`use_lockfile` vs `.terraform.lock.hcl`:** These are unrelated. `use_lockfile = true` is S3 state locking. `.terraform.lock.hcl` is the local provider-version pin file written by `terraform init`; it MUST be committed to Git.
- **`force_destroy = false`** in all environments (dev/staging/prod). State buckets are critical; accidental deletion is intentionally disallowed.
- **Account ID sourced from authenticated provider data** (`data.aws_caller_identity.current.account_id`) rather than trusted from tfvars. Region remains a variable (default `us-east-1`) because the provider cannot be initialized from a data source (cycle).
- **Lock file permissions:** `s3:GetObject`/`s3:PutObject`/`s3:DeleteObject` on `terraform.tfstate.tflock` (role must be able to acquire and release the state lock). `s3:DeleteObject` is NOT granted on `terraform.tfstate` (state-object deletion guard).

**Requirements Satisfied:** R2 (state management foundation)

**Dependencies:** T01-01

**Security Considerations:** S3 bucket must have versioning enabled, block public access, and encryption at rest (SSE-S3 minimum). `force_destroy` must be `false` in all environments. Two-stage bootstrap: Stage 1 contains ONLY security `Deny` statements (no role-scoped `Allow`); Stage 2 (post-T01-07) adds role-scoped `Allow` statements. Never write a placeholder or nonexistent role ARN into a bucket policy. Preserve administrative recovery path via bucket ownership.

**Acceptance Criteria:**
1. S3 bucket created with versioning enabled, block-public-access-all set, SSE-S3 encryption, `force_destroy = false`
2. Backend uses `use_lockfile = true` (S3 state lock via `<state_key>.tflock`); no DynamoDB lock table required. `use_lockfile` is S3 state locking and is unrelated to `.terraform.lock.hcl` (the local provider-version pin file, which must be committed to Git).
3. Stage 1 bucket policy contains ONLY security `Deny` statements (insecure-transport, unencrypted-uploads); no role-scoped `Allow` statements in Stage 1
4. Stage 2 (post-T01-07) adds: role-scoped `AllowListBucketForStateDiscovery` (prefix-condition), `AllowStateObjectReadWrite` (state key only), `AllowStateLockFileReadWrite` (`.tflock` key with GetObject/PutObject/DeleteObject), and `DenyStateObjectDeletion` on `terraform.tfstate` (NOT on `.tflock`). Deploy role ARN validated via regex `^arn:aws:iam::[0-9]{12}:role/.+$` (IAM users rejected).
5. Account ID sourced from `data.aws_caller_identity.current` (authenticated provider data) rather than trusted from tfvars
6. Backend configuration documented in `terraform/backend/README.md` with copy-paste `backend {}` block including `use_lockfile = true` and no `dynamodb_table`, plus the Stage-2 bucket-policy template
7. Terraform state file upload tested with `terraform init -migrate-state` (post-apply verification)

**Tests Required:** Terraform plan must succeed against the configured backend with 0 undeclared-variable warnings; state lock test with two parallel `terraform plan` calls (second must fail with lock error)

**Expected Cost Impact:** 🟡[CHARGES] ~$0.01/month (S3 storage only; no DynamoDB)

**Manual Verification (POST-APPLY — COMPLETED 2026-09-03):** `aws s3api get-bucket-versioning` returns Enabled; `aws s3api get-bucket-policy` shows 2 Deny statements in Stage 1 (insecure-transport, unencrypted-uploads); state-lock test with two `terraform plan` calls passed (both acquired and released the lock cleanly, no `.tflock` residue). Stage 2 (post-T01-07) plan remains pending — will be prepared once the Terraform deploy role ARN exists.

---

### Task T01-03: Configure Terraform Providers and AWS Authentication

**Objective:** Define the Terraform provider configuration supporting multi-account access via AWS SSO and role assumption.

**Files/Components Affected:** 	erraform/environments/common/providers.tf, 	erraform/environments/common/variables.tf, 	erraform/environments/common/locals.tf

**AWS Services Involved:** IAM (STS), AWS SSO

**Requirements Satisfied:** R17 (multi-account foundation)

**Dependencies:** T01-02

**Security Considerations:** Never hardcode access keys. Use AWS SSO role assumption with explicit session tags. Provider must set default_tags for organization-wide tagging.

**Acceptance Criteria:**
1. Provider block defines aliases for Security Account and each Workload Account
2. Each alias uses ssume_role with role ARN variable
3. default_tags configured with Project, Environment, ManagedBy, CostCenter
4. Provider configuration validated with 	erraform validate
5. 	erraform plan succeeds against at least one account

**Tests Required:** 	erraform validate passes; 	erraform plan with mock credentials succeeds (provider resolution)

**Expected Cost Impact:** 

**Manual Verification:** Run 	erraform providers and confirm all account aliases resolve; run 	erraform plan and confirm no credential errors

---

### Task T01-04: Establish Development Environment and Tooling

**Objective:** Define and document the local development environment including Python version, Terraform version, AWS CLI configuration, and required tools.

**Files/Components Affected:** .python-version, .terraform-version, pyproject.toml, 	erraform/environments/dev/backend.hcl, docs/development.md, scripts/setup-dev.sh

**AWS Services Involved:** None (local setup)

**Requirements Satisfied:** R2 (dev foundation)

**Dependencies:** T01-01

**Security Considerations:** Dev environment must not have access to production IAM roles. Dev profile uses a dedicated IAM user or SSO role with minimal permissions.

**Acceptance Criteria:**
1. Python 3.11+ version pinned; Lambda runtime matches (Python 3.11)
2. Terraform 1.6+ version pinned
3. pyproject.toml lists all dependencies: boto3, pytest, pytest-cov, jinja2, requests, botocore, moto
4. 	erraform/environments/dev/backend.hcl points to dev backend
5. scripts/setup-dev.sh creates virtualenv and installs all dependencies
6. docs/development.md documents how to configure AWS credentials and run Terraform

**Tests Required:** python -m pytest --version succeeds; 	erraform version matches pinned version

**Expected Cost Impact:** 

**Manual Verification:** Run setup script in clean environment; confirm all tools install and python -c "import boto3, pytest" succeeds

---

### Task T01-05: Define Naming and Tagging Standards

**Objective:** Establish organization-wide naming conventions for all CloudSec AI resources and mandatory tagging requirements.

**Files/Components Affected:** 	erraform/environments/common/naming.tf, 	erraform/environments/common/tags.tf, docs/naming-standards.md

**AWS Services Involved:** None (standards document, Terraform locals)

**Requirements Satisfied:** R17 (operational standards)

**Dependencies:** T01-01

**Security Considerations:** Tags must include Environment (dev/staging/prod) to enable cost allocation and security filtering. ManagedBy tag required for all resources.

**Acceptance Criteria:**
1. All resource names follow pattern: cloudsec-{env}-{component}-{unique-id}
2. Mandatory tags defined: Project, Environment, ManagedBy, CostCenter, CreatedBy, IncidentClassification (for security resources)
3. Terraform locals define all naming templates
4. docs/naming-standards.md provides examples for every resource type used (S3, DynamoDB, Lambda, SQS, SNS, EventBridge, KMS, IAM, Step Functions)

**Tests Required:** None (standards)

**Expected Cost Impact:** 

**Manual Verification:** Review naming-standards.md; confirm all resources in Phase 1+ use the naming convention

---

### Task T01-06: Deploy KMS Foundation (Customer-Managed Keys)

**Objective:** Create the customer-managed KMS keys used by all CloudSec AI components for encryption at rest.

**Files/Components Affected:** 	erraform/modules/kms/ (incident-data-key, evidence-bucket-key, finding-encryption-key, ssm-parameter-key)

**AWS Services Involved:** KMS

**Requirements Satisfied:** R14 (evidence preservation encryption), R2 (incident data encryption)

**Dependencies:** T01-05

**Security Considerations:** 🟠[IAM-CHANGE] Each KMS key has a restricted key policy allowing only specific principals. Key rotation enabled. Keys use explicit key aliases. Pending deletion window set to 30 days for safety.

**Acceptance Criteria:**
1. Four CMKs created: cloudsec-{env}-incident-key, cloudsec-{env}-evidence-key, cloudsec-{env}-finding-key, cloudsec-{env}-ssm-key
2. Each key has automatic rotation enabled
3. Key policy restricts usage to specific IAM roles (defined per service)
4. Key aliases follow naming standard (e.g., lias/cloudsec/dev/incident)
5. deletion_window_in_days set to 30

**Tests Required:** ws kms decrypt succeeds with a known plaintext/ciphertext pair for each key; cross-account access denied test

**Expected Cost Impact:** 🔴[HARD-TO-DELETE] 🟡[CHARGES] ~.10/key/month (.40/month total); KMS keys require 7-30 day deletion window

**Manual Verification:** List keys via ws kms list-aliases; confirm rotation status; attempt decryption with valid and invalid principals

---

### Task T01-07: Establish IAM Foundations (Service Roles and Policies)

**Objective:** Create the base IAM roles and policies that all CloudSec AI Lambda functions and Step Functions will assume.

**Files/Components Affected:** 	erraform/modules/iam/ (roles: investigation-role, correlation-role, safety-validation-role, remediation-role, verification-role, reporting-role; policies: kms-access, dynamodb-access, s3-access, bedrock-access, cloudtrail-access, guardduty-access)

**AWS Services Involved:** IAM, KMS

**Requirements Satisfied:** R2, R6, R8, R9, R13, R15, R16

**Dependencies:** T01-06

**Security Considerations:** 🟠[IAM-CHANGE] Every policy uses least-privilege (specific ARNs, not wildcards). Trust policies restrict role assumption to specific Lambda/Step Functions service principals. No inline policies with broad permissions.

**Acceptance Criteria:**
1. Six service roles created with specific trust policies (Lambda and Step Functions service principals only)
2. Each role has a scoped IAM policy granting only the permissions that component needs
3. KMS key access is explicitly granted per key per role
4. No role has * as Action or Resource in any statement
5. Policy documents include comments explaining each permission
6. Roles are deployable in both dev and prod with environment-specific ARNs

**Tests Required:** IAM policy validation via ws iam simulate-principal-policy for each role; confirm denied actions for out-of-scope resources

**Expected Cost Impact:** 🟠[IAM-CHANGE]  (IAM roles are free)

**Manual Verification:** ws iam get-role for each role; run simulate-principal-policy with test actions; confirm scoped permissions

---

### Task T01-08: Implement Cost Controls and Budgets

**Objective:** Set up cost monitoring, budgets, and spending limits before deploying any billable resources.

**Files/Components Affected:** 	erraform/modules/cost-controls/ (budget, anomaly detection, cost allocation tags)

**AWS Services Involved:** AWS Budgets, Cost Explorer, CloudWatch

**Requirements Satisfied:** R17 (observability/cost)

**Dependencies:** T01-05

**Security Considerations:** Budget notifications sent to Security Account SNS topic to ensure visibility across accounts.

**Acceptance Criteria:**
1. AWS Budget created with monthly limit of  (dev),  (prod)
2. Budget alert configured at 80%, 100%, and 120% of limit
3. Anomaly detection enabled for the CloudSec AI cost allocation tag
4. SNS topic cloudsec-{env}-cost-alerts created for budget notifications
5. Cost allocation tags documented in docs/cost-controls.md

**Tests Required:** Simulate budget threshold (manual) and confirm SNS notification fires

**Expected Cost Impact:** 🟡[CHARGES] Budget alerts are free; anomaly detection adds ~ (included in Billing and Cost Management)

**Manual Verification:** Navigate to AWS Budgets console and confirm budget exists with correct thresholds; confirm SNS topic created


---

## Phase 2: Core Incident Platform

**Goal:** Build the central incident data layer, event bus, and state management — the backbone on which all investigation and remediation logic depends.

**Danger Flags in this phase:** 🟡[CHARGES] (DynamoDB, EventBridge, SQS, SNS), 🟠[IAM-CHANGE] (EventBridge rules, SQS policies)

**Manual Checkpoint:** End of Phase 2 — verify event bus delivers events end-to-end before proceeding to telemetry ingestion.

### Task T02-01: Create DynamoDB Incident Table

**Objective:** Deploy the primary DynamoDB table for incident records with partition key, sort key, GSI, TTL, and encryption.

**Files/Components Affected:** 	erraform/modules/dynamodb/incident-table.tf

**AWS Services Involved:** DynamoDB, KMS

**Requirements Satisfied:** R2 (incident creation, lifecycle, retention, status transitions)

**Dependencies:** T01-06 (KMS key), T01-05 (naming)

**Security Considerations:** Table encrypted with customer-managed KMS key. Point-in-time recovery enabled for 35 days. Backup retention set to 35 days.

**Acceptance Criteria:**
1. Table cloudsec-{env}-incidents created with partition key incident_id (String) and sort key event_time (String, ISO 8601)
2. GSI indings-index on inding_id (String) + event_time
3. GSI status-index on status (String) + event_time
4. SSE with cloudsec-{env}-incident-key
5. Point-in-time recovery window set to 35 days
6. TTL attribute 	tl (Number) configured for auto-expiry
7. Table tags match naming standards

**Tests Required:** Write/read/delete item via ws dynamodb put-item/get-item/delete-item; GSI query test; confirm KMS encryption

**Expected Cost Impact:** 🟡[CHARGES] ~-10/month at dev scale (DynamoDB on-demand)

**Manual Verification:** ws dynamodb describe-table --table-name cloudsec-dev-incidents; write a test item and query via GSI; confirm encryption type is KMS

---

### Task T02-02: Create DynamoDB Findings Table

**Objective:** Deploy the DynamoDB table for storing normalized security findings with indexing for correlation queries.

**Files/Components Affected:** 	erraform/modules/dynamodb/findings-table.tf

**AWS Services Involved:** DynamoDB, KMS

**Requirements Satisfied:** R1 (telemetry ingestion), R4 (correlation)

**Dependencies:** T02-01, T01-06

**Security Considerations:** SSE-KMS encryption. Findings may contain IPs, ARNs — all data must be encrypted at rest.

**Acceptance Criteria:**
1. Table cloudsec-{env}-findings with partition key inding_id (String) and sort key ingested_at (String, ISO 8601)
2. GSI principal-index on principal_arn + ingested_at
3. GSI source-ip-index on source_ip + ingested_at
4. GSI 
esource-index on 
esource_arn + ingested_at
5. GSI ccount-index on source_account + ingested_at
6. KMS encryption with cloudsec-{env}-finding-key
7. PITR enabled (35 days)

**Tests Required:** Put-item with all indexed attributes; query each GSI; confirm encryption

**Expected Cost Impact:** 🟡[CHARGES] ~-20/month at dev scale

**Manual Verification:** ws dynamodb describe-table; insert test findings and verify all GSIs return results

---

### Task T02-03: Deploy EventBridge Security Bus (Custom Event Bus)

**Objective:** Create a dedicated EventBridge custom event bus for internal security events, isolating platform events from default AWS events.

**Files/Components Affected:** 	erraform/modules/eventbridge/security-bus.tf

**AWS Services Involved:** EventBridge

**Requirements Satisfied:** R2 (event routing), R1 (ingestion routing)

**Dependencies:** T01-05

**Security Considerations:** Event bus is internal-only; no cross-account permissions on the bus itself. Rules route to specific targets.

**Acceptance Criteria:**
1. Custom event bus cloudsec-{env}-security-bus created
2. Event bus has no public access; permissions scoped to specific IAM roles
3. 	erraform import command documented for existing bus
4. Bus policy denies non-platform principals

**Tests Required:** ws events put-events with the bus name succeeds; event appears in EventBridge console

**Expected Cost Impact:** 🟡[CHARGES] ~.01/1M events (negligible at dev scale)

**Manual Verification:** ws events describe-event-bus --name cloudsec-dev-security-bus; put a test event and confirm it appears in the event history

---

### Task T02-04: Create Dead Letter Queue and Retry Configuration

**Objective:** Deploy SQS DLQ for failed event processing with 14-day retention and associated CloudWatch metrics.

**Files/Components Affected:** 	erraform/modules/sqs/dlq.tf

**AWS Services Involved:** SQS, CloudWatch, KMS

**Requirements Satisfied:** R1 (parse failure handling), R2 (error handling)

**Dependencies:** T01-06

**Security Considerations:** DLQ encrypted with SSE-KMS. Access restricted to platform Lambda functions and a dedicated recovery role.

**Acceptance Criteria:**
1. SQS queue cloudsec-{env}-dlq created with 14-day message retention
2. KMS SSE enabled with cloudsec-{env}-finding-key
3. Queue policy allows only the correlation-engine Lambda and investigation-engine Lambda to receive messages
4. Redrive policy configured on all processing queues pointing to DLQ (maxReceiveCount: 3)
5. CloudWatch metric filter DLQDepth created for alerting

**Tests Required:** Send a test message to DLQ; confirm it is visible; confirm processing Lambda cannot receive it (policy check)

**Expected Cost Impact:** 🟡[CHARGES] ~.50/month

**Manual Verification:** ws sqs get-queue-attributes --queue-url <dlq-url>; confirm RetentionPeriod=1209600 (14 days); confirm KmsMasterKeyId set

---

### Task T02-05: Define Internal Event Schema

**Objective:** Define the canonical JSON schema for all internal platform events (finding-ingested, incident-created, investigation-started, remediation-executed, etc.).

**Files/Components Affected:** schemas/finding-event.json, schemas/incident-event.json, schemas/investigation-event.json, schemas/remediation-event.json, schemas/common-types.json

**AWS Services Involved:** None (schema definition only)

**Requirements Satisfied:** R1, R2, R6, R8, R9, R13, R15, R16

**Dependencies:** None

**Security Considerations:** Schema must include event_id (UUID), event_type (enum), 	imestamp (ISO 8601), source_account, source_region, principal_arn (optional), 
esource_arn (optional). No PII fields. Schema must use $id for referenceable types.

**Acceptance Criteria:**
1. Six event types defined: FindingIngested, IncidentCreated, IncidentStatusChanged, InvestigationStarted, InvestigationCompleted, RemediationExecuted, RemediationVerified, RemediationFailed
2. Common types defined: AccountId, Arn, IpAddress, Timestamp, Severity (enum: P1-P4), Status (enum: OPEN, INVESTIGATING, REMEDIATING, VERIFYING, RESOLVED, ESCALATED)
3. All schemas pass $schema validation with jsonschema library
4. Python dataclasses generated from schemas in lambda/common/models.py
5. Schema version field schema_version (semver string) included in all events

**Tests Required:** pytest with jsonschema validates each schema against sample payloads; invalid payloads are rejected

**Expected Cost Impact:** 

**Manual Verification:** Open each JSON schema file; run python -c "import jsonschema; jsonschema.validate(...)" with sample payload

---

### Task T02-06: Implement Incident State Machine (DynamoDB Item Handler)

**Objective:** Build the Python library that enforces incident status transitions in DynamoDB with optimistic locking.

**Files/Components Affected:** lambda/common/incident_state.py, lambda/common/incident_lifecycle.py, 	ests/unit/test_incident_state.py

**AWS Services Involved:** DynamoDB

**Requirements Satisfied:** R2 (status transitions, retention, DynamoDB retries)

**Dependencies:** T02-01

**Security Considerations:** Uses DynamoDB ConditionExpression with ersion attribute for optimistic concurrency control. Invalid transitions must be rejected atomically.

**Acceptance Criteria:**
1. Valid transitions defined as constant dict: OPEN -> INVESTIGATING, INVESTIGATING -> REMEDIATING, REMEDIATING -> VERIFYING, VERIFYING -> RESOLVED, VERIFYING -> ESCALATED
2. 	ransition_incident(incident_id, new_status, reason) function uses DynamoDB UpdateItem with ConditionExpression ttribute_exists(incident_id) AND status = :current
3. On ConditionCheckFailedException, raise InvalidTransitionError with current and attempted status
4. create_incident(findings, severity) function with idempotency key support
5. get_incident(incident_id) function with error handling for DynamoDB unavailability
6. Retry decorator (max 3 retries, exponential backoff starting at 1s) applied to DynamoDB operations
7. Unit tests cover: valid transition, invalid transition, missing incident, DynamoDB error, concurrent update conflict

**Tests Required:** 8+ unit tests (valid transitions x5, invalid transition x3, missing incident, DynamoDB error retry, concurrent update)

**Expected Cost Impact:** 

**Manual Verification:** Run unit tests; manually test optimistic lock conflict via two simultaneous 	ransition_incident calls

---

### Task T02-07: Deploy SNS Notification Topics

**Objective:** Create the SNS topics used for incident notifications, cost alerts, and error notifications.

**Files/Components Affected:** 	erraform/modules/sns/notification-topics.tf

**AWS Services Involved:** SNS, KMS

**Requirements Satisfied:** R2 (escalation notification), R17 (alerting)

**Dependencies:** T01-06

**Security Considerations:** SNS topics encrypted with KMS. Subscription policies restrict who can subscribe. No email subscriptions for automated topics.

**Acceptance Criteria:**
1. Topic cloudsec-{env}-incidents created (incident lifecycle notifications)
2. Topic cloudsec-{env}-escalations created (escalation/verification failure alerts)
3. Topic cloudsec-{env}-errors created (system error notifications)
4. All topics KMS-encrypted with cloudsec-{env}-incident-key
5. Topics tagged per naming standard

**Tests Required:** ws sns publish succeeds to each topic; subscription creation succeeds

**Expected Cost Impact:** 🟡[CHARGES] ~.50/month

**Manual Verification:** ws sns list-topics; confirm KmsMasterKeyId on each; publish test message and confirm delivery

---

### Task T02-08: Deploy EventBridge Rules for Internal Event Routing

**Objective:** Create EventBridge rules on the custom security bus that route events to the correct processing targets.

**Files/Components Affected:** 	erraform/modules/eventbridge/rules.tf

**AWS Services Involved:** EventBridge, Lambda, SQS

**Requirements Satisfied:** R2 (event routing), R4 (correlation triggering)

**Dependencies:** T02-03, T02-04

**Security Considerations:** 🟠[IAM-CHANGE] Each rule has a target-role that restricts which Lambda can be invoked. Dead letter configuration on each rule points to DLQ.

**Acceptance Criteria:**
1. Rule inding-ingested matches detail-type=FindingIngested, routes to correlation-engine Lambda
2. Rule incident-created matches detail-type=IncidentCreated, routes to investigation-engine Lambda
3. Rule investigation-completed matches detail-type=InvestigationCompleted, routes to safety-validation Lambda
4. Rule investigation-failed matches detail-type=InvestigationFailed, routes to DLQ
5. Each rule has dead-letter-config pointing to DLQ ARN
6. Each rule has 	arget-role-arn set to a dedicated invocation role
7. No rule matches on the default bus

**Tests Required:** ws events put-events to custom bus; confirm target Lambda is invoked (CloudWatch Logs check)

**Expected Cost Impact:** 🟡[CHARGES] ~.01/1M rules evaluations (negligible)

**Manual Verification:** ws events list-rules --event-bus-name cloudsec-dev-security-bus; confirm DLQ ARN on each rule; publish test event and verify Lambda invocation in logs

**CHECKPOINT — Phase 2 Review:** Before proceeding to Phase 3, manually verify: (1) custom event bus exists and accepts events, (2) DynamoDB tables exist with correct GSIs and encryption, (3) DLQ has 14-day retention, (4) EventBridge rules fire targets correctly, (5) incident state machine rejects invalid transitions.


---

## Phase 3: Security Telemetry

**Goal:** Ingest and normalize security signals from all supported AWS telemetry sources into the common internal event schema.

**Danger Flags in this phase:** 🟡[CHARGES] (CloudTrail, Security Hub, GuardDuty), 🔴[HARD-TO-DELETE] (CloudTrail trail, S3 buckets), 🟠[IAM-CHANGE] (Cross-account permissions)

**Manual Checkpoint:** End of Phase 3 — verify at least one telemetry source delivers a normalized event to the DynamoDB findings table before proceeding.

### Task T03-01: Deploy GuardDuty EventBridge Rule and Ingestion Lambda

**Objective:** Configure an EventBridge rule to capture GuardDuty Finding events and route them to a Lambda that normalizes and stores findings.

**Files/Components Affected:** 	erraform/modules/eventbridge/guardduty-rule.tf, lambda/ingestion/guardduty_ingestor.py, lambda/ingestion/normalizer.py, 	ests/unit/test_guardduty_ingestor.py

**AWS Services Involved:** GuardDuty, EventBridge, Lambda, DynamoDB, SQS

**Requirements Satisfied:** R1 (GuardDuty ingestion, parse failure handling, event tagging)

**Dependencies:** T02-02 (findings table), T02-03 (event bus), T02-04 (DLQ)

**Security Considerations:** EventBridge rule matches only GuardDuty finding events. Lambda role has least-privilege: DynamoDB PutItem on findings table, EventBridge PutEvents on security bus, SQS SendMessage on DLQ. GuardDuty must be enabled in the Security Account first.

**Acceptance Criteria:**
1. EventBridge rule guardduty-findings on the default bus matches source=aws.guardduty and detail-type=GuardDuty Finding
2. Lambda cloudsec-{env}-guardduty-ingestor receives events and:
   - Validates event structure against expected GuardDuty Finding schema
   - Extracts: finding_id, severity, resource_arn, principal_arn (if present), service_name, event_id, region, account_id
   - Tags event with source_account, source_region, 
eceived_at
   - Writes normalized finding to DynamoDB findings table
   - Publishes FindingIngested event to security bus
3. Invalid/malformed events are sent to DLQ with original payload
4. CloudWatch metric ParseFailure emitted for each parse failure
5. Lambda timeout set to 30 seconds, memory 512 MB
6. Lambda has reserved concurrency of 5

**Tests Required:** Unit tests for: valid GuardDuty event normalization, missing fields handling, malformed JSON handling, DynamoDB write failure, DLQ routing on failure

**Expected Cost Impact:** 🟡[CHARGES] GuardDuty ~-5/month per account (varies by account size); Lambda invocation negligible

**Manual Verification:** Enable GuardDuty in Security Account; use ws guardduty create-ip-set with a known test IP to trigger a finding; confirm finding appears in DynamoDB within 5 minutes; confirm FindingIngested event on security bus

---

### Task T03-02: Deploy Security Hub EventBridge Rule and Ingestion Lambda

**Objective:** Configure an EventBridge rule to capture Security Hub findings (MEDIUM+) and route them to a normalization Lambda.

**Files/Components Affected:** 	erraform/modules/eventbridge/securityhub-rule.tf, lambda/ingestion/securityhub_ingestor.py, 	ests/unit/test_securityhub_ingestor.py

**AWS Services Involved:** Security Hub, EventBridge, Lambda, DynamoDB

**Requirements Satisfied:** R1 (Security Hub ingestion with severity filtering)

**Dependencies:** T02-02, T02-03, T03-01 (reusable normalizer)

**Security Considerations:** Rule filters on severity MEDIUM, HIGH, CRITICAL only. Lambda has least-privilege DynamoDB WriteAccess.

**Acceptance Criteria:**
1. EventBridge rule securityhub-findings matches source=aws.securityhub and detail-type=Security Hub Findings - Imported
2. Input transformer or Lambda filter excludes severity LOW and INFORMATIONAL
3. Lambda normalizes Security Hub ASFF findings to internal schema
4. Deduplication: if inding_id already exists in DynamoDB with same updated_at, skip write
5. All acceptance criteria from T03-01 for DLQ routing, metric emission, and event publishing

**Tests Required:** Unit tests for: MEDIUM/HIGH/CRITICAL findings ingested, LOW/INFORMATIONAL excluded, duplicate finding deduplication, malformed ASFF

**Expected Cost Impact:** 🟡[CHARGES] Security Hub ~-10/month per account

**Manual Verification:** ws securityhub enable-security-hub; ws securityhub batch-import-findings with test ASFF at each severity level; confirm only MEDIUM+ in DynamoDB

---

### Task T03-03: Configure Multi-Region Organization-Level CloudTrail

**Objective:** Deploy an organization-level CloudTrail trail that delivers management events to an S3 bucket in the Security Account.

**Files/Components Affected:** 	erraform/modules/cloudtrail/org-trail.tf, 	erraform/modules/s3/cloudtrail-bucket.tf

**AWS Services Involved:** CloudTrail, S3, KMS, IAM

**Requirements Satisfied:** R1 (CloudTrail ingestion from all Workload Accounts)

**Dependencies:** T01-06 (KMS), T01-07 (IAM)

**Security Considerations:** 🟠[IAM-CHANGE] Trail delivers to Security Account S3 bucket. S3 bucket policy denies all non-CloudTrail access. KMS key in Security Account decrypts logs. Trail includes log file validation (SHA256). Multi-region enabled. Organization trail with management events only.

**Acceptance Criteria:**
1. CloudTrail cloudsec-{env}-org-trail created as an organization trail
2. Trail is multi-region (is_multi_region_trail = true)
3. Trail includes is_management_trail = true, include_global_service_events = true
4. Trail delivers to S3 bucket cloudsec-{env}-cloudtrail-logs-{account} with prefix CloudTrail/
5. S3 bucket has versioning enabled, SSE-S3, block-public-access, object-lock in COMPLIANCE mode
6. Trail enabled (enable_log_file_validation = true, is_logging = true)
7. S3 bucket policy denies all access except CloudTrail AWS service

**Tests Required:** CloudTrail describe-trails confirms multi-region and org trail; S3 bucket policy review

**Expected Cost Impact:** 🔴[HARD-TO-DELETE] 🟡[CHARGES] ~-30/month depending on API volume; S3 bucket with object-lock is difficult to delete

**Manual Verification:** ws cloudtrail describe-trails confirms multi_region_trail=true and include_global_service_events=true; ws s3 ls s3://cloudsec-dev-cloudtrail-logs-{account}/ shows CloudTrail log files after 24 hours

---

### Task T03-04: Deploy CloudTrail Log Parser Lambda and EventBridge Partner Event

**Objective:** Deploy a Lambda that processes CloudTrail log files from S3, normalizes CloudTrail events, and publishes them as platform events.

**Files/Components Affected:** 	erraform/modules/s3/cloudtrail-notification.tf, lambda/ingestion/cloudtrail_parser.py, 	ests/unit/test_cloudtrail_parser.py

**AWS Services Involved:** S3, Lambda, DynamoDB, EventBridge, SQS

**Requirements Satisfied:** R1 (CloudTrail ingestion), R4 (correlation data)

**Dependencies:** T03-03, T02-02, T02-03

**Security Considerations:** Lambda role can only read CloudTrail S3 bucket and write to findings table. No s3:* permissions.

**Acceptance Criteria:**
1. S3 bucket notification on .json.gz files in CloudTrail/ prefix triggers Lambda
2. Lambda decompresses and parses each CloudTrail record
3. Each record normalized to internal schema: event_name, event_source, user_identity.arn, source_ip_address, 
esources[].ARN, event_time, ws_region, 
equest_parameters, 
esponse_elements, error_code
4. Events written to DynamoDB findings table
5. FindingIngested event published to security bus for management events
6. Batch processing: Lambda processes up to 1000 records per invocation
7. Lambda timeout 60 seconds, memory 1024 MB

**Tests Required:** Unit tests for: valid CloudTrail record parsing, malformed JSON handling, multi-record batch processing, missing fields, DynamoDB write failure

**Expected Cost Impact:** 🟡[CHARGES] Lambda invocation ~.02/GB-second; S3 notification events negligible

**Manual Verification:** Trigger a test API call in the account; wait for CloudTrail log delivery; confirm Lambda invocation in CloudWatch Logs; confirm finding in DynamoDB

---

### Task T03-05: Deploy AWS Config Aggregator and Config Change Ingestion Lambda

**Objective:** Configure AWS Config to aggregate configuration changes from all Workload Accounts and ingest them into the platform.

**Files/Components Affected:** 	erraform/modules/awsconfig/aggregator.tf, lambda/ingestion/config_ingestor.py, 	ests/unit/test_config_ingestor.py

**AWS Services Involved:** AWS Config, EventBridge, Lambda, DynamoDB, KMS

**Requirements Satisfied:** R1 (AWS Config ingestion)

**Dependencies:** T02-02, T02-03, T01-06

**Security Considerations:** 🟠[IAM-CHANGE] Config aggregator requires cross-account role ConfigConfigRecorderRole in each Workload Account. Aggregator in Security Account has least-privilege.

**Acceptance Criteria:**
1. AWS Config aggregator cloudsec-{env}-config-aggregator created in Security Account
2. Aggregator aggregates configuration items from all Workload Accounts
3. Lambda cloudsec-{env}-config-ingestor triggered by Config configuration change notifications via EventBridge
4. Lambda normalizes Config events: resource_type, resource_id, account_id, region, configuration, tags, related_resources
5. Events written to findings table with source=aws_config
6. FindingIngested event published for configuration changes

**Tests Required:** Unit tests for: valid Config change event, missing configuration field, unknown resource type

**Expected Cost Impact:** 🟡[CHARGES] AWS Config ~-5/account/month

**Manual Verification:** ws configservice describe-configuration-aggregators; modify an S3 bucket policy in a Workload Account; confirm Config event appears in DynamoDB within 5 minutes

---

### Task T03-06: Configure VPC Flow Logs Ingestion to Security Lake

**Objective:** Deploy VPC Flow Logs delivery to Amazon Security Lake in the Security Account.

**Files/Components Affected:** 	erraform/modules/securitylake/collector.tf, 	erraform/modules/securitylake/fleet.tf

**AWS Services Involved:** Security Lake, VPC, EventBridge, Lambda

**Requirements Satisfied:** R1 (VPC Flow Logs ingestion)

**Dependencies:** T01-06

**Security Considerations:** Security Lake collector requires IAM role with VPC access across accounts. 🟠[IAM-CHANGE] Cross-account permissions needed.

**Acceptance Criteria:**
1. Security Lake enabled in Security Account
2. Data collector configured for VPC Flow Logs in all Workload Accounts
3. Fleet and tables created for flow-log ingestion
4. Athena queries available for flow log analysis
5. VPC Flow Logs configured at subnet level for tagged VPCs (platform monitoring tag)
6. Documented process for adding new Workload Accounts

**Tests Required:** ws securitylake describe-collectors; Athena query on flow logs table returns results

**Expected Cost Impact:** 🟡[CHARGES] ~-15/month (Security Lake + Athena + S3 storage)

**Manual Verification:** Generate network traffic in a tagged VPC; confirm flow logs appear in Security Lake within 10 minutes; run Athena query on flow_logs table

**CHECKPOINT — Phase 3 Review:** Before proceeding to Phase 4, manually verify: (1) GuardDuty findings appear in DynamoDB, (2) Security Hub MEDIUM+ findings appear in DynamoDB, (3) CloudTrail events appear in DynamoDB, (4) Config changes appear in DynamoDB, (5) all findings use the normalized internal schema, (6) parse failures route to DLQ.


---

## Phase 4: Correlation Engine

**Goal:** Build the event correlation engine that groups related findings into incidents based on principal, IP, resource, and time-window logic.

**Danger Flags in this phase:** 🟠[IAM-CHANGE] (Lambda role for DynamoDB batch reads)

### Task T04-01: Implement Finding Correlation Data Access Layer

**Objective:** Build the DynamoDB query functions used by the correlation engine to fetch related findings.

**Files/Components Affected:** lambda/common/dynamodb/findings_repo.py, lambda/common/dynamodb/incidents_repo.py, 	ests/unit/test_findings_repo.py

**AWS Services Involved:** DynamoDB

**Requirements Satisfied:** R4 (correlation data access)

**Dependencies:** T02-01, T02-02

**Security Considerations:** Functions use explicit table names from environment variables. No hardcoded ARNs. IAM policy scoped to specific table actions.

**Acceptance Criteria:**
1. get_findings_by_principal(principal_arn, start_time, end_time) — query principal-index GSI
2. get_findings_by_source_ip(source_ip, start_time, end_time) — query source-ip-index GSI
3. get_findings_by_resource(resource_arn, start_time, end_time) — query resource-index GSI
4. get_findings_by_account(account_id, start_time, end_time) — query account-index GSI
5. get_findings_in_window(start_time, end_time, max_items=1000) — scan with time filter
6. All functions return typed dataclass objects
7. Retry decorator with 3 retries, exponential backoff on DynamoDB errors
8. Pagination handled for queries returning >1000 items

**Tests Required:** moto-based integration tests simulating DynamoDB; test each query function with seeded data; test pagination with >1000 items

**Expected Cost Impact:** 

**Manual Verification:** Deploy Lambda with test data; call each function via Step Functions invoke; verify returned data matches seeded findings

---

### Task T04-02: Implement Principal ARN Correlation

**Objective:** Build the correlation logic that groups findings by common principal ARN within a configurable time window.

**Files/Components Affected:** lambda/correlation/principal_correlator.py, 	ests/unit/test_principal_correlator.py

**AWS Services Involved:** None (pure Python logic)

**Requirements Satisfied:** R4 (principal ARN correlation)

**Dependencies:** T04-01

**Security Considerations:** Correlation must not leak findings across account boundaries unless explicitly configured for cross-account correlation.

**Acceptance Criteria:**
1. correlate_by_principal(findings, window_minutes=15) groups findings sharing the same principal_arn within the time window
2. Window is sliding: for each finding, all other findings within ±window_minutes are candidates
3. Cross-account correlation: findings from different accounts but same principal ARN are correlated only if cross_account_correlation config flag is True
4. Role assumption chains are handled: if principal A assumed role B, both A and B are considered the same identity
5. Groups of size < 2 are not correlated (single finding does not form an incident)
6. Each group has a correlation_type=principal_arn tag

**Tests Required:** Unit tests for: two findings same principal same window, two findings same principal different windows (not correlated), role chain resolution, cross-account blocking, single finding (no correlation)

**Expected Cost Impact:** 

**Manual Verification:** Run unit tests; manually verify with test data that two GuardDuty findings from the same principal within 15 minutes are grouped

---

### Task T04-03: Implement Source IP Correlation

**Objective:** Build the correlation logic that groups findings by common source IP address within a configurable time window.

**Files/Components Affected:** lambda/correlation/ip_correlator.py, 	ests/unit/test_ip_correlator.py

**AWS Services Involved:** None (pure Python logic)

**Requirements Satisfied:** R4 (source IP correlation)

**Dependencies:** T04-01

**Security Considerations:** Public IPs from AWS services (Amazon S3, AWS Lambda egress, etc.) must be excluded from IP correlation to avoid false positives. AWS IP range file is used for exclusion.

**Acceptance Criteria:**
1. correlate_by_ip(findings, window_minutes=30) groups findings sharing the same source_ip within the time window
2. AWS service IPs are excluded (loaded from docs/aws-ip-ranges.json, updated via scheduled Lambda daily)
3. Well-known scanner IPs (Shodan, Censys, etc.) are flagged but excluded from correlation
4. Findings with no source_ip field are not correlated by IP
5. Each group has a correlation_type=source_ip tag
6. Multiple IPs from the same findings set do not force correlation across IPs

**Tests Required:** Unit tests for: same IP same window, same IP different window, AWS IP exclusion, missing IP, multiple distinct IPs in same finding set

**Expected Cost Impact:** 

**Manual Verification:** Run unit tests; verify AWS IP exclusion with known AWS egress IP

---

### Task T04-04: Implement Resource ARN Correlation

**Objective:** Build the correlation logic that groups findings by common resource ARN (same resource attacked multiple times).

**Files/Components Affected:** lambda/correlation/resource_correlator.py, 	ests/unit/test_resource_correlator.py

**AWS Services Involved:** None (pure Python logic)

**Requirements Satisfied:** R4 (resource ARN correlation)

**Dependencies:** T04-01

**Security Considerations:** Resource ARN comparison must handle ARN aliases and path variations (e.g., rn:aws:iam::123:role/admin vs rn:aws:iam::123:role/team/admin).

**Acceptance Criteria:**
1. correlate_by_resource(findings, window_minutes=60) groups findings sharing the same 
esource_arn within the time window
2. ARN normalization handles: trailing slashes, case-insensitive service names, region variations (global vs regional ARN)
3. Wildcard ARNs in findings are excluded from resource correlation
4. Findings without 
esource_arn are not correlated by resource
5. Each group has a correlation_type=resource_arn tag

**Tests Required:** Unit tests for: same resource same window, ARN normalization, wildcard exclusion, missing resource ARN

**Expected Cost Impact:** 

**Manual Verification:** Run unit tests; manually verify with two findings referencing the same S3 bucket ARN

---

### Task T04-05: Implement Time-Window Logic and Tie-Breaking

**Objective:** Build the configurable time-window mechanism and tie-breaking rules for the correlation engine.

**Files/Components Affected:** lambda/correlation/time_window.py, lambda/correlation/tie_breaker.py, lambda/correlation/config.py, 	ests/unit/test_time_window.py, 	ests/unit/test_tie_breaker.py

**AWS Services Involved:** SSM Parameter Store

**Requirements Satisfied:** R4 (time-window logic, tie-breaking)

**Dependencies:** T04-02, T04-03, T04-04

**Security Considerations:** Window durations must be configurable per correlation type via SSM parameters. Default windows: principal=15min, IP=30min, resource=60min. Tie-breaking must prefer higher-severity findings.

**Acceptance Criteria:**
1. Time window configuration stored in SSM: /cloudsec/{env}/correlation/principal_window_minutes, /cloudsec/{env}/correlation/ip_window_minutes, /cloudsec/{env}/correlation/resource_window_minutes
2. Window is symmetric (±window_minutes from each finding's timestamp)
3. Overlapping windows merge: if finding A and B overlap with finding C, they all form one group
4. Tie-breaking rules (in order): (a) higher severity wins, (b) earlier timestamp wins, (c) alphabetically lower finding_id wins
5. Correlation config loaded at Lambda init time, reloaded every 5 minutes
6. Correlation results include metadata: correlation_type, window_start, window_end, inding_count, severity_distribution

**Tests Required:** Unit tests for: window overlap merging, tie-breaking each rule, config reload, missing config parameter (default values)

**Expected Cost Impact:** 

**Manual Verification:** Run unit tests; update SSM parameter and confirm new window duration is used on next invocation

---

### Task T04-06: Implement Incident Grouping and Creation Logic

**Objective:** Combine all correlation types and produce incident records in DynamoDB.

**Files/Components Affected:** lambda/correlation/incident_builder.py, lambda/correlation/correlation_engine.py, 	ests/unit/test_incident_builder.py, 	ests/integration/test_correlation_engine.py

**AWS Services Involved:** DynamoDB, EventBridge, Lambda

**Requirements Satisfied:** R4 (incident grouping), R2 (incident creation within 10 seconds)

**Dependencies:** T04-02, T04-03, T04-04, T04-05, T02-06

**Security Considerations:** Incident creation must be idempotent: same set of findings must not create duplicate incidents. Uses DynamoDB conditional write with composite key.

**Acceptance Criteria:**
1. correlate_findings(findings) runs all three correlators and merges results
2. Same finding can appear in multiple correlation groups but is assigned to only the highest-priority group
3. Incident severity = highest severity among constituent findings (CRITICAL->P1, HIGH->P2, MEDIUM->P3, LOW->P4)
4. Incident creation uses DynamoDB PutItem with ConditionExpression ttribute_not_exists(incident_id) for idempotency
5. If incident already exists (duplicate detection), return existing incident without creating new one
6. IncidentCreated event published to security bus with incident details
7. Execution time must be <10 seconds for up to 1000 findings (measured in integration tests)
8. Unit tests cover: single finding (no incident), two findings correlated, multiple groups formed, duplicate incident prevention, severity mapping

**Tests Required:** 10+ unit tests; 2+ integration tests using moto DynamoDB and mocked EventBridge

**Expected Cost Impact:** 

**Manual Verification:** Insert test findings in DynamoDB; invoke correlation engine; confirm incident created in DynamoDB incidents table; confirm IncidentCreated event on security bus


---

## Phase 5: Behavior Baseline

**Goal:** Build deterministic and statistical behavior baselines before introducing AI — these provide the "normal activity" context that the AI Investigation Engine uses to identify anomalies.

**Danger Flags in this phase:** 🟡[CHARGES] (DynamoDB baselines table, Lambda scheduled execution)

**Manual Checkpoint:** End of Phase 5 — verify baselines are generated from CloudTrail data and confidence scores are computed correctly before introducing AI.

### Task T05-01: Create Behavior Baselines DynamoDB Table

**Objective:** Deploy the DynamoDB table storing per-principal behavior baselines.

**Files/Components Affected:** 	erraform/modules/dynamodb/baselines-table.tf

**AWS Services Involved:** DynamoDB, KMS

**Requirements Satisfied:** R5 (behavior baseline storage)

**Dependencies:** T01-06, T01-05

**Security Considerations:** Table encrypted with KMS. Baselines contain behavioral data about principals — sensitive information requiring strict access control.

**Acceptance Criteria:**
1. Table cloudsec-{env}-baselines with partition key principal_arn (String) and sort key aseline_date (String, YYYY-MM-DD)
2. GSI ccount-index on source_account + aseline_date
3. SSE-KMS with cloudsec-{env}-finding-key
4. TTL attribute 	tl for auto-expiry of baselines older than 90 days
5. PITR enabled (35 days)

**Tests Required:** Write/read/delete test baseline item; confirm GSI query works

**Expected Cost Impact:** 🟡[CHARGES] ~/month at dev scale

**Manual Verification:** ws dynamodb describe-table; insert test baseline and query by principal

---

### Task T05-02: Implement Baseline Computation Lambda

**Objective:** Build the Lambda that computes behavior baselines from 30 days of historical CloudTrail data.

**Files/Components Affected:** lambda/baselines/compute_baseline.py, lambda/baselines/normalizer.py, 	ests/unit/test_compute_baseline.py

**AWS Services Involved:** CloudTrail (lookup), DynamoDB, SSM

**Requirements Satisfied:** R5 (baseline computation, confidence signaling for shorter windows)

**Dependencies:** T05-01, T04-01

**Security Considerations:** Lambda uses CloudTrail LookupEvents API (management events only, last 90 days). Principal ARNs are used as identifiers — no credential material is accessed.

**Acceptance Criteria:**
1. For each principal ARN found in CloudTrail data, compute:
   - 
ormal_regions: set of regions where the principal typically operates
   - common_api_calls: top 20 API action names with frequency
   - common_services: set of AWS service names accessed
   - 	ypical_hours: set of UTC hours with activity (0-23)
   - common_assumed_roles: set of roles assumed by this principal
   - ctivity_count_30d: total management event count in 30 days
   - confidence_score: 1.0 if 30+ days of data, 0.5 if 7-29 days, 0.2 if <7 days
2. Baselines computed once per principal per day (idempotent by principal_arn + aseline_date)
3. CloudTrail pagination handled (LookupEvents returns max 50 events per call)
4. New principals (no historical data) are flagged with confidence_score=0.0 and 
ew_principal=true
5. Computation takes <30 seconds per principal

**Tests Required:** Unit tests for: full baseline computation, new principal handling, confidence score for short window, CloudTrail pagination, malformed CloudTrail event

**Expected Cost Impact:** 🟡[CHARGES] CloudTrail LookupEvents ~.0001/event; Lambda invocation negligible

**Manual Verification:** Run Lambda manually for a known IAM user; confirm baseline record in DynamoDB with populated fields; verify confidence score based on data window

---

### Task T05-03: Deploy Scheduled Baseline Computation EventBridge Rule

**Objective:** Configure a daily scheduled EventBridge rule to trigger baseline computation for all principals.

**Files/Components Affected:** 	erraform/modules/eventbridge/baseline-schedule.tf

**AWS Services Involved:** EventBridge, Lambda

**Requirements Satisfied:** R5 (scheduled baseline refresh)

**Dependencies:** T05-02, T02-03

**Security Considerations:** Schedule runs during low-traffic hours (03:00 UTC). Reserved concurrency prevents baseline Lambda from impacting investigation Lambda.

**Acceptance Criteria:**
1. EventBridge scheduled rule aseline-computation triggers at 03:00 UTC daily
2. Rule targets the baseline computation Lambda with payload containing {\"mode\": \"daily_refresh\"}
3. Lambda reserved concurrency set to 2 (baseline only)
4. CloudWatch alarm aseline-computation-failure fires if Lambda fails for 2 consecutive days

**Tests Required:** Manual trigger of scheduled event; confirm Lambda invocation

**Expected Cost Impact:** 🟡[CHARGES] EventBridge schedule ~.01/1M invocations (negligible)

**Manual Verification:** ws events list-rules; manually invoke the schedule target; confirm baseline table updated

---

### Task T05-04: Implement Baseline Anomaly Detection Logic

**Objective:** Build the logic that compares incoming findings against stored baselines and produces anomaly scores.

**Files/Components Affected:** lambda/baselines/anomaly_detector.py, 	ests/unit/test_anomaly_detector.py

**AWS Services Involved:** DynamoDB

**Requirements Satisfied:** R5 (anomaly detection against baselines)

**Dependencies:** T05-01, T05-02

**Security Considerations:** Anomaly detection must not trigger false positives on legitimate new principals. Confidence score <0.5 means anomaly scores are not produced (insufficient data).

**Acceptance Criteria:**
1. detect_anomalies(finding, baseline) returns dict with:
   - nomaly_score (0.0-1.0, 1.0 = maximum anomaly)
   - nomaly_reasons: list of strings explaining why anomalous
   - aseline_confidence: copied from baseline
2. Anomaly signals:
   - Activity in a region not in 
ormal_regions → +0.3
   - API call not in common_api_calls → +0.2
   - Activity outside 	ypical_hours (±2 hours) → +0.2
   - New role assumption not in common_assumed_roles → +0.3
   - No baseline exists → return nomaly_score=0.5, 
eason=\"new_principal\"
3. If aseline_confidence < 0.5, return nomaly_score=None (insufficient data)
4. Anomaly scores capped at 1.0
5. Anomaly results included in the Investigation Report evidence package (Phase 6)

**Tests Required:** Unit tests for: normal activity (score <0.3), new region activity, new API call, off-hours activity, new role, no baseline, low confidence

**Expected Cost Impact:** 

**Manual Verification:** Run unit tests; manually compare a finding against a baseline with known unusual activity; confirm anomaly score >0.5

**CHECKPOINT — Phase 5 Review:** Before proceeding to Phase 6, manually verify: (1) baselines table contains records for active principals, (2) scheduled computation runs daily, (3) anomaly detector produces reasonable scores for normal vs unusual activity, (4) new principals are handled correctly with low confidence.


---

## Phase 6: AI Investigation Engine

**Goal:** Build the Amazon Bedrock integration that produces structured investigation reports from evidence packages, with strict schema validation, citation requirements, and hallucination controls.

**Danger Flags in this phase:** 🟡[CHARGES] (Bedrock API calls), 🟠[IAM-CHANGE] (Bedrock permissions), ⚠️[SECURITY-RISK] (AI output handling), 🟡[CHARGES] (SSM, CloudWatch)

### Task T06-01: Configure Bedrock Model Access and SSM Parameters

**Objective:** Enable Amazon Bedrock model access in the target region and configure model selection through SSM Parameter Store.

**Files/Components Affected:** 	erraform/modules/bedrock/model-access.tf, 	erraform/modules/ssm/investigation-config.tf

**AWS Services Involved:** Bedrock, SSM, IAM

**Requirements Satisfied:** R6 (model configuration through SSM), R17 (observability of Bedrock calls)

**Dependencies:** T01-07

**Security Considerations:** 🟠[IAM-CHANGE] Bedrock model invocation policy attached to investigation Lambda role only. No other Lambda has Bedrock access. Model ID stored in SSM, not hardcoded.

**Acceptance Criteria:**
1. Bedrock model access enabled for Anthropic Claude 3.5 Sonnet (and optionally Claude 3.5 Haiku for cost-sensitive)
2. IAM policy cloudsec-{env}-bedrock-access allows only edrock:InvokeModel and edrock:InvokeModelWithResponseStream
3. Policy scoped to specific model ARNs (no wildcard on model ID)
4. SSM parameters created:
   - /cloudsec/{env}/ai/model_id (default: nthropic.claude-3-5-sonnet-20241022-v2:0)
   - /cloudsec/{env}/ai/max_tokens (default: 4096)
   - /cloudsec/{env}/ai/temperature (default:  .0)
   - /cloudsec/{env}/ai/timeout_seconds (default: 60)
   - /cloudsec/{env}/ai/retry_max (default: 3)
5. Model access confirmed via ws bedrock list-foundation-models

**Tests Required:** ws bedrock list-foundation-models confirms model is available; SSM parameter read test

**Expected Cost Impact:** 🟡[CHARGES] Bedrock invocation ~.003/1K input tokens, ~.015/1K output tokens (Claude Sonnet); dev usage ~-20/month

**Manual Verification:** ws bedrock list-foundation-models returns the model; ws ssm get-parameter confirms all parameters exist with correct values

---

### Task T06-02: Implement Evidence Packaging Logic

**Objective:** Build the Lambda function that assembles evidence packages for a given incident from all sources.

**Files/Components Affected:** lambda/investigation/evidence_packager.py, 	ests/unit/test_evidence_packager.py

**AWS Services Involved:** DynamoDB, CloudTrail, Security Hub

**Requirements Satisfied:** R6 (evidence packaging), R7 (attack reconstruction data)

**Dependencies:** T04-01, T05-01, T06-01

**Security Considerations:** Evidence packaging must not include full CloudTrail 
equest_parameters that may contain secrets (passwords, tokens). Sensitive fields are redacted before packaging.

**Acceptance Criteria:**
1. package_evidence(incident_id) assembles:
   - All findings from the incident (from findings table)
   - Correlation metadata (correlation type, window, finding count)
   - Behavior baselines for all principals in findings
   - Anomaly detection results
   - Blast radius data (from Phase 8, if available)
   - Timeline events (from Phase 7, if available)
2. Sensitive fields redacted: 
equestParameters.password, 
equestParameters.accessKey, 
equestParameters.secretKey, 
equestParameters.token
3. Evidence package size capped at 4000 tokens (input to Bedrock); excess evidence is summarized
4. Evidence includes evidence_id (UUID) for each item, enabling citation cross-reference validation
5. Package includes incident_id, severity, created_at, evidence_count metadata

**Tests Required:** Unit tests for: full evidence package assembly, redaction of sensitive fields, size capping/truncation, missing baselines handling, empty findings

**Expected Cost Impact:**  (data assembly only)

**Manual Verification:** Run unit tests; manually invoke with a test incident; confirm evidence IDs are present and sensitive fields redacted

---

### Task T06-03: Define Investigation Report JSON Schema

**Objective:** Define the strict JSON Schema that all Bedrock investigation responses must conform to.

**Files/Components Affected:** schemas/investigation-report-schema.json, lambda/investigation/schema_validator.py, 	ests/unit/test_schema_validator.py

**AWS Services Involved:** None (schema definition)

**Requirements Satisfied:** R6 (strict JSON output schema, schema validation, citation requirements)

**Dependencies:** T06-02

**Security Considerations:** ⚠️[SECURITY-RISK] Schema must not allow unbounded string lengths. All arrays have maxItems. All strings have maxLength. Response is the single source of truth for remediation decisions.

**Acceptance Criteria:**
1. Schema defines these top-level fields (all required):
   - incident_id (string, maxLength=64)
   - summary (string, maxLength=2000, executive-level summary)
   - confidence_score (number, 0.0-1.0)
   - ttack_stage (string, enum: [reconnaissance, initial_access, credential_access, privilege_escalation, defense_evasion, persistence, lateral_movement, collection, command_and_control, exfiltration, impact])
   - mitre_attack_techniques (array of strings, maxItems=10, maxLength=16 each, format: T1234)
   - ffected_principals (array of objects, maxItems=10)
   - ffected_resources (array of objects, maxItems=20)
   - evidence_citations (array of objects, maxItems=20, each has evidence_id and quote)
   - 	imeline_summary (string, maxLength=2000)
   - 
ecommended_actions (array of objects, maxItems=5, each has ction, severity, 
ationale)
2. Schema passes $schema validation
3. Python dataclass InvestigationReport generated from schema
4. alidate_report(report_json) raises SchemaValidationError with specific field-level error messages

**Tests Required:** Unit tests for: valid report passes, missing field fails, oversized string fails, invalid enum fails, maxItems exceeded fails, non-JSON input fails

**Expected Cost Impact:** 

**Manual Verification:** Open schema file; run jsonschema.validate() with valid and invalid payloads

---

### Task T06-04: Implement Bedrock Investigation Lambda

**Objective:** Build the main Lambda that invokes Bedrock with structured prompts and validates responses against the schema.

**Files/Components Affected:** lambda/investigation/bedrock_investigator.py, lambda/investigation/prompt_builder.py, 	ests/unit/test_bedrock_investigator.py, 	ests/unit/test_prompt_builder.py

**AWS Services Involved:** Bedrock, DynamoDB, EventBridge, SSM, CloudWatch

**Requirements Satisfied:** R6 (structured prompts, Bedrock integration, retry/timeout, AI must never execute remediation)

**Dependencies:** T06-01, T06-02, T06-03

**Security Considerations:** ⚠️[SECURITY-RISK] Lambda must never call AWS APIs that perform state-changing actions (no Delete*, Detach*, Modify*, Put* except DynamoDB write of the report). Bedrock output is never executed — only validated and stored. Prompt explicitly instructs model to never suggest executing code.

**Acceptance Criteria:**
1. investigate(incident_id) Lambda:
   - Loads Bedrock config from SSM
   - Calls package_evidence(incident_id)
   - Builds structured prompt (see T06-04 prompt template)
   - Invokes Bedrock with model from SSM, max_tokens from SSM, temperature=0
   - Parses response as JSON
   - Validates against investigation report schema
   - On schema validation failure: retry up to 
etry_max times with regenerated prompt
   - On all retries exhausted: emit InvestigationFailed event, return error
   - On success: write report to DynamoDB incidents table, emit InvestigationCompleted event
2. Prompt template includes:
   - Role: "You are a cloud security incident analyst"
   - Evidence section with numbered evidence IDs
   - Strict JSON output instructions
   - Citation requirement: "Every conclusion must cite at least one evidence_id"
   - "Do not execute any AWS commands" instruction
   - Schema reference embedded in prompt
3. Response parsing handles Bedrock stop_reason=LENGTH by retrying with shorter prompt
4. CloudWatch metrics emitted: BedrockInvocation, BedrockSuccess, BedrockFailure, SchemaValidationError
5. Lambda timeout: 90 seconds, memory: 1024 MB

**Tests Required:** Unit tests (with mocked Bedrock) for: successful investigation, schema validation failure with retry, all retries exhausted, malformed JSON response, Bedrock timeout, LENGTH stop_reason; integration test with real Bedrock call (optional, dev only)

**Expected Cost Impact:** 🟡[CHARGES] Bedrock calls ~.01-0.05 per investigation (varies by evidence size); ~-30/month dev usage

**Manual Verification:** Invoke Lambda with test incident; confirm DynamoDB record updated with InvestigationCompleted; check CloudWatch logs for Bedrock response

---

### Task T06-05: Implement Schema Validation and Evidence Cross-Reference Validator

**Objective:** Build the post-investigation validation layer that checks citations against provided evidence and enforces hallucination controls.

**Files/Components Affected:** lambda/investigation/citation_validator.py, lambda/investigation/hallucination_checker.py, 	ests/unit/test_citation_validator.py, 	ests/unit/test_hallucination_checker.py

**AWS Services Involved:** DynamoDB

**Requirements Satisfied:** R6 (citation requirements, evidence cross-reference validation, hallucination controls)

**Dependencies:** T06-02, T06-03

**Security Considerations:** ⚠️[SECURITY-RISK] Any investigation report with uncited conclusions is automatically flagged and cannot proceed to remediation. This is a critical safety control.

**Acceptance Criteria:**
1. alidate_citations(report, evidence_package) checks:
   - Every evidence_citation.evidence_id exists in the evidence package
   - Every evidence_citation.quote is a substring of the corresponding evidence item's content
   - All findings in the incident are referenced by at least one citation
2. check_hallucinations(report, evidence_package) checks:
   - ffected_principals list contains only ARNs found in evidence
   - ffected_resources list contains only ARNs found in evidence
   - mitre_attack_techniques are valid MITRE ATT&CK IDs
   - ttack_stage is consistent with evidence (e.g., "exfiltration" requires S3/transfer events)
3. Validation failure results in InvestigationReport marked alidation_status=REJECTED in DynamoDB
4. Reports with alidation_status=REJECTED cannot proceed to Phase 9 (Safety Validation Engine)

**Tests Required:** Unit tests for: valid citations pass, non-existent evidence_id fails, quote mismatch fails, ARN not in evidence fails, invalid MITRE ID fails, attack_stage inconsistency

**Expected Cost Impact:** 

**Manual Verification:** Run unit tests; manually test with a report citing non-existent evidence; confirm validation fails

---

### Task T06-06: Implement Retry and Timeout Handler for Bedrock

**Objective:** Build the retry logic with exponential backoff and timeout handling specifically for Bedrock calls.

**Files/Components Affected:** lambda/common/bedrock_client.py, 	ests/unit/test_bedrock_client.py

**AWS Services Involved:** Bedrock, CloudWatch

**Requirements Satisfied:** R6 (retry/timeout behavior)

**Dependencies:** T06-01

**Security Considerations:** Retry logic must not mask authentication failures indefinitely. Auth errors (AccessDeniedException) are never retried.

**Acceptance Criteria:**
1. invoke_bedrock(prompt, model_id, max_tokens, temperature) wraps the Bedrock SDK call
2. Retry behavior:
   - ThrottlingException: retry with exponential backoff (1s, 2s, 4s, 8s), max 
etry_max attempts
   - ServiceUnavailableException: retry with exponential backoff, max 
etry_max attempts
   - AccessDeniedException: NEVER retry, raise immediately
   - ValidationError: NEVER retry (prompt issue), raise immediately
   - ModelInvocationException (LENGTH): retry once with halved max_tokens
3. Timeout: each Bedrock call has a 45-second socket timeout (Lambda has 90s total)
4. Each retry increments CloudWatch metric BedrockRetryCount with dimension 
etry_reason
5. Final failure emits CloudWatch metric BedrockFinalFailure

**Tests Required:** Unit tests for: throttling retry succeeds on 2nd attempt, service unavailable retry succeeds, access denied never retried, validation error never retried, LENGTH retry with halved tokens, final failure after all retries

**Expected Cost Impact:** 

**Manual Verification:** Run unit tests; simulate throttling with mocked Bedrock; confirm retry behavior


---

## Phase 7: Attack Reconstruction

**Goal:** Build the timeline reconstruction and attack-stage classification engine that converts correlated findings into a coherent attack narrative.

**Danger Flags in this phase:** ⚠️[SECURITY-RISK] (timeline accuracy affects all downstream decisions)

### Task T07-01: Implement Timeline Reconstruction Logic

**Objective:** Build the logic that orders all evidence events chronologically and identifies timeline gaps.

**Files/Components Affected:** lambda/reconstruction/timeline_builder.py, 	ests/unit/test_timeline_builder.py

**AWS Services Involved:** DynamoDB, CloudTrail

**Requirements Satisfied:** R7 (timeline reconstruction, timeline-gap handling)

**Dependencies:** T04-06, T05-04

**Security Considerations:** Timeline must include events from all accounts in the correlation group. Timestamps normalized to UTC ISO 8601.

**Acceptance Criteria:**
1. uild_timeline(incident_id) retrieves all findings and CloudTrail events for the incident's time window
2. Events sorted chronologically by event_time (UTC)
3. Each event in timeline includes: event_time, event_type, principal_arn, 
esource_arn, event_name, source_account, 
egion, evidence_id
4. Timeline gap detection: if gap between consecutive events exceeds 60 minutes, mark as 	imeline_gap with start/end times
5. Timeline includes a gap_analysis field describing each gap
6. Timeline capped at 200 events (earliest 100 + latest 100 if more)

**Tests Required:** Unit tests for: chronological ordering, gap detection (gap >60min), gap detection (no gap), timestamp normalization, event cap enforcement

**Expected Cost Impact:** 

**Manual Verification:** Run unit tests; manually verify with findings spanning 2 hours with a 90-minute gap; confirm gap is detected

---

### Task T07-02: Implement Attack-Stage Classification

**Objective:** Build the logic that classifies each timeline event into an attack stage using rule-based heuristics.

**Files/Components Affected:** lambda/reconstruction/attack_stages.py, 	ests/unit/test_attack_stages.py

**AWS Services Involved:** None (pure Python logic)

**Requirements Satisfied:** R7 (attack-stage classification)

**Dependencies:** T07-01

**Security Considerations:** Classification is deterministic and auditable — no AI involvement at this stage to avoid hallucination of attack stages.

**Acceptance Criteria:**
1. Event-to-stage mapping rules (evaluated in priority order):
   - UnauthorizedAccess, UnauthorizedAPI findings → initial_access
   - ConsoleLogin with unknown IP → credential_access
   - CreateAccessKey, AttachRolePolicy, PutUserPolicy → privilege_escalation
   - StopLogging, DeleteTrail, DisableCloudTrail → defense_evasion
   - CreateUser, PutLoginProfile, CreateKeyPair → persistence
   - AssumeRole across accounts → lateral_movement
   - GetObject, ListBuckets on sensitive S3 → collection
   - CreateNatGateway, AuthorizeSecurityGroupIngress on 0.0.0.0/0 → command_and_control
   - PutBucketPublicAccessBlock set to false → exfiltration
2. Each event tagged with ttack_stage (one of 11 MITRE stages)
3. Events that match no rule tagged ttack_stage=unknown
4. Timeline stage sequence validated: stages must follow MITRE order (no impact before initial_access)
5. Invalid stage sequences flagged as stage_anomaly

**Tests Required:** Unit tests for: each rule matches correctly, unknown event tagging, stage sequence validation, stage anomaly detection

**Expected Cost Impact:** 

**Manual Verification:** Run unit tests; manually verify that a CloudTrail CreateAccessKey event is classified as privilege_escalation

---

### Task T07-03: Implement MITRE ATT&CK Mapping

**Objective:** Assign MITRE ATT&CK for Cloud technique IDs to classified timeline events where evidence justifies it.

**Files/Components Affected:** lambda/reconstruction/mitre_mapper.py, docs/mitre-technique-map.json, 	ests/unit/test_mitre_mapper.py

**AWS Services Involved:** None

**Requirements Satisfied:** R7 (MITRE ATT&CK mapping)

**Dependencies:** T07-02

**Security Considerations:** Mapping is conservative: only assign a technique ID when the evidence strongly supports it. Unknown or ambiguous events are not assigned techniques.

**Acceptance Criteria:**
1. Technique map in docs/mitre-technique-map.json maps event types to ATT&CK IDs
2. Rules:
   - CreateAccessKey + AttachRolePolicy → T1098 (Account Manipulation)
   - AssumeRole on privileged role → T1548 (Abuse Elevation Control Mechanism)
   - StopLogging/DeleteTrail → T1562 (Impair Defenses)
   - PutBucketPublicAccessBlock → T1530 (Data from Cloud Storage)
3. Each technique assignment includes 	echnique_id, 	echnique_name, evidence_ids (list of supporting evidence)
4. Only assign technique if at least 1 supporting evidence event exists
5. Technique list deduplicated (same technique from multiple events appears once)

**Tests Required:** Unit tests for: valid technique assignment, insufficient evidence (no assignment), deduplication

**Expected Cost Impact:** 

**Manual Verification:** Run unit tests; verify technique map JSON is valid; confirm T1098 assigned when CreateAccessKey is in timeline

---

### Task T07-04: Implement Cross-Account Labeling

**Objective:** Tag timeline events with cross-account activity labels for multi-account incidents.

**Files/Components Affected:** lambda/reconstruction/cross_account_labeler.py, 	ests/unit/test_cross_account_labeler.py

**AWS Services Involved:** None

**Requirements Satisfied:** R7 (cross-account labeling)

**Dependencies:** T07-01

**Security Considerations:** Cross-account activity is a strong indicator of lateral movement and must be clearly labeled.

**Acceptance Criteria:**
1. Each timeline event tagged with cross_account: true/false based on whether principal_arn account differs from 
esource_arn account
2. AssumeRole events that cross accounts tagged with lateral_movement: true
3. Summary field: cross_account_summary lists unique account pairs involved
4. Cross-account events get +0.1 confidence boost for attack severity

**Tests Required:** Unit tests for: same-account event (cross_account=false), cross-account AssumeRole, cross-account API call, account pair summary

**Expected Cost Impact:** 

**Manual Verification:** Run unit tests; verify cross-account AssumeRole is correctly labeled

---

### Task T07-05: Integrate Reconstruction into Investigation Report

**Objective:** Wire timeline, attack stages, and MITRE mapping into the investigation report evidence package.

**Files/Components Affected:** lambda/reconstruction/reconstruction_orchestrator.py, lambda/investigation/evidence_packager.py (update)

**AWS Services Involved:** DynamoDB

**Requirements Satisfied:** R7 (timeline in report), R6 (evidence for AI)

**Dependencies:** T07-01, T07-02, T07-03, T07-04

**Security Considerations:** Reconstruction data is included as evidence for the AI investigation — must be properly redacted (same redaction rules as T06-02).

**Acceptance Criteria:**
1. 
econstruct_attack(incident_id) runs all reconstruction stages and returns structured result
2. Result includes: 	imeline (ordered events with stages), ttack_stages_detected (unique stages), mitre_techniques (assigned techniques), cross_account_summary, 	imeline_gaps
3. Result stored in DynamoDB incidents table under 
econstruction field
4. Evidence packager (T06-02) includes reconstruction data in Bedrock prompt
5. Reconstruction runs before Bedrock invocation in the investigation workflow

**Tests Required:** Integration test: incident with 5 findings → reconstruction produces timeline with stages and techniques

**Expected Cost Impact:** 

**Manual Verification:** Invoke reconstruction for a test incident; confirm DynamoDB record has 
econstruction field with timeline, stages, and techniques


---

## Phase 8: Blast Radius

**Goal:** Build the blast radius analysis engine that determines which resources, roles, and permissions are reachable from a compromised identity.

**Danger Flags in this phase:** 🟡[CHARGES] (IAM Policy Simulator API calls), 🟠[IAM-CHANGE] (Lambda role needs IAM read permissions)

### Task T08-01: Implement IAM Policy Simulator Integration

**Objective:** Build the Lambda function that uses the IAM Policy Simulator to determine what actions a compromised principal can perform.

**Files/Components Affected:** lambda/blast_radius/policy_simulator.py, 	ests/unit/test_policy_simulator.py

**AWS Services Involved:** IAM (SimulateCustomPolicy, SimulatePrincipalPolicy)

**Requirements Satisfied:** R8 (IAM Policy Simulator integration, confirmed reachable resources)

**Dependencies:** T04-06 (incident with principal ARNs)

**Security Considerations:** 🟠[IAM-CHANGE] Lambda needs iam:SimulateCustomPolicy and iam:SimulatePrincipalPolicy (read-only IAM operations). No permission to modify IAM. Policy Simulator is read-only — no state changes.

**Acceptance Criteria:**
1. simulate_permissions(principal_arn, action_filter=None) calls SimulatePrincipalPolicy
2. Returns: llowed_actions (list of actions permitted), denied_actions (list of actions denied), implicit_denied (list of actions not explicitly allowed or denied)
3. Supports optional ction_filter to test specific actions (e.g., s3:DeleteBucket, iam:CreateUser)
4. Results cached for 5 minutes per principal_arn (SSM or in-memory)
5. Pagination handled for principals with many policies
6. Error handling: if principal not found, return error=\"principal_not_found\"

**Tests Required:** Unit tests (mocked IAM) for: allowed action, denied action, implicit deny, principal not found, multiple policies combined, action filter

**Expected Cost Impact:** 🟡[CHARGES] IAM Policy Simulator is free for up to 10,000 calls/month; Lambda invocation negligible

**Manual Verification:** Test with a known IAM user; confirm allowed/denied actions match manual policy review; confirm caching works (2nd call <100ms)

---

### Task T08-02: Implement Static Policy Fallback

**Objective:** Build the fallback analysis for principals when the Policy Simulator is unavailable or returns incomplete results.

**Files/Components Affected:** lambda/blast_radius/static_analyzer.py, 	ests/unit/test_static_analyzer.py

**AWS Services Involved:** IAM (list-attached-role-policies, get-role-policy)

**Requirements Satisfied:** R8 (static fallback for Policy Simulator)

**Dependencies:** T08-01

**Security Considerations:** Static analysis is approximate — it evaluates explicit allow/deny but does not account for SCPs, permission boundaries, or service control policies. Results are marked nalysis_method=static to distinguish from simulator results.

**Acceptance Criteria:**
1. static_analyze(principal_arn) retrieves all attached and inline policies for a role or user
2. Evaluates explicit allow and deny statements
3. Returns: explicitly_allowed, explicitly_denied, conditions (list of condition keys used)
4. Marked nalysis_method=static and confidence=medium (vs nalysis_method=simulator, confidence=high)
5. Falls back to static analysis if Policy Simulator returns LimitExceeded or ServiceUnavailable
6. Results merged with simulator results: static fills gaps where simulator has no data

**Tests Required:** Unit tests for: role with attached policy, user with inline policy, explicit deny overrides allow, condition keys extracted, fallback from simulator failure

**Expected Cost Impact:** 

**Manual Verification:** Test with a role that has an explicit deny; confirm static analyzer correctly identifies the deny

---

### Task T08-03: Implement Role Assumption Path Analysis

**Objective:** Build the logic that traces role assumption chains to find all roles reachable from a compromised principal.

**Files/Components Affected:** lambda/blast_radius/role_chain_analyzer.py, 	ests/unit/test_role_chain_analyzer.py

**AWS Services Involved:** IAM (list-roles, get-role)

**Requirements Satisfied:** R8 (role assumption paths)

**Dependencies:** T08-01

**Security Considerations:** Role chain analysis is BFS/DFS — must handle cycles (role A trusts role B trusts role A). Maximum depth of 5 hops to prevent infinite loops.

**Acceptance Criteria:**
1. ind_assumable_roles(starting_principal_arn) traverses trust policies
2. For each role, checks if starting_principal_arn appears in trust policy as Principal
3. BFS traversal with max depth 5
4. Cycle detection: if a role appears twice in the path, traversal stops at that branch
5. Returns: 
eachable_roles (list of ARNs), ssumption_paths (list of paths from start to each role), max_depth_reached
6. Results include privilege_level for each reachable role: dmin, power_user, 
ead_only, custom (based on attached managed policies)

**Tests Required:** Unit tests for: direct trust relationship, multi-hop chain, cycle detection, max depth enforcement, no reachable roles

**Expected Cost Impact:** 

**Manual Verification:** Test with a known role trust chain; confirm all reachable roles are found; confirm cycle doesn't cause infinite loop

---

### Task T08-04: Implement Sensitive Resource Classification

**Objective:** Build the logic that classifies AWS resources into sensitivity levels for blast radius impact assessment.

**Files/Components Affected:** lambda/blast_radius/resource_classifier.py, docs/sensitive-resource-patterns.json, 	ests/unit/test_resource_classifier.py

**AWS Services Involved:** None

**Requirements Satisfied:** R8 (sensitive-resource classification)

**Dependencies:** T04-01 (findings with resource ARNs)

**Security Considerations:** Classification is conservative — when in doubt, classify as sensitive. Patterns include known high-value resources (KMS keys, IAM roles, S3 buckets with known data types).

**Acceptance Criteria:**
1. Classification levels: critical, high, medium, low
2. Rules (from sensitive-resource-patterns.json):
   - IAM roles/policies/users → critical
   - KMS keys → critical
   - S3 buckets with data or database or ackup in name → high
   - RDS instances → high
   - Secrets Manager secrets → critical
   - Security groups → medium
   - Lambda functions → medium
   - EC2 instances → medium
   - S3 buckets (default) → low
   - Other resources → low
3. S3 bucket names can be overridden via a manual override list in SSM
4. Each classification includes 
eason explaining why

**Tests Required:** Unit tests for: each classification level, override handling, unknown resource type, pattern matching

**Expected Cost Impact:** 

**Manual Verification:** Test with a known KMS key ARN; confirm classified as critical

---

### Task T08-05: Implement Blast Radius Risk Scoring

**Objective:** Combine all blast radius data into a single risk score and structured report.

**Files/Components Affected:** lambda/blast_radius/risk_scoring.py, lambda/blast_radius/blast_radius_orchestrator.py, 	ests/unit/test_risk_scoring.py

**AWS Services Involved:** DynamoDB

**Requirements Satisfied:** R8 (risk scoring, blast radius report)

**Dependencies:** T08-01, T08-02, T08-03, T08-04

**Security Considerations:** Risk score is purely a function of deterministic data (no AI). Score components are auditable and reproducible.

**Acceptance Criteria:**
1. compute_blast_radius(incident_id) orchestrates all analysis and returns:
   - principal_permissions: list of {action, effect} for each compromised principal
   - 
eachable_roles: list of role ARNs and assumption paths
   - ffected_resources: list of resources with sensitivity classification
   - 
isk_score (0.0-10.0):
     - +2.0 per critical resource reachable
     - +1.0 per high resource reachable
     - +0.5 per medium resource reachable
     - +3.0 if admin role is reachable
     - +2.0 if cross-account role reachable
     - +1.0 per 10 allowed actions
     - Cap at 10.0
   - 
isk_level: CRITICAL (8-10), HIGH (5-7.9), MEDIUM (3-4.9), LOW (<3)
   - 	op_risk_factors: top 3 factors contributing to score
2. Report stored in DynamoDB incidents table under last_radius field
3. Report includes nalysis_timestamp, nalysis_method for each component

**Tests Required:** Unit tests for: scoring calculation (each factor), score capping, risk level mapping, top factors extraction, empty blast radius (score=0)

**Expected Cost Impact:** 

**Manual Verification:** Run with a compromised admin role; confirm risk_score >= 8.0 and risk_level = CRITICAL


---

## Phase 9: Safety Validation Engine

**Goal:** Build the deterministic safety validation layer that receives AI remediation recommendations and enforces strict Level 3 → Level 2 → Level 1 precedence before any execution.

**This phase must be complete BEFORE any automated remediation is implemented.**

**Danger Flags in this phase:** ⚠️[SECURITY-RISK] (this is the primary safety control preventing unauthorized automated actions), 🟠[IAM-CHANGE] (policy validation needs IAM read)

**Manual Checkpoint:** End of Phase 9 — verify the safety engine blocks Level 3 recommendations and requires approval for Level 2 before proceeding to remediation.

### Task T09-01: Define Approved Action Policy

**Objective:** Create the machine-readable policy defining all permissible remediation actions, their allowed parameter ranges, and applicability conditions.

**Files/Components Affected:** docs/approved-action-policy.json, lambda/safety/policy_store.py, 	ests/unit/test_policy_store.py

**AWS Services Involved:** None

**Requirements Satisfied:** R9 (approved action policy)

**Dependencies:** T06-03 (investigation schema provides 
ecommended_actions)

**Security Considerations:** ⚠️[SECURITY-RISK] This policy is the single source of truth for what the platform is allowed to do. It must be reviewed and approved by a security engineer before any Level 1 action is permitted. Changes to this policy require a pull request and security review.

**Acceptance Criteria:**
1. Policy defines actions for each remediation scenario:
   - disable_iam_key: allowed_params: {user_name, access_key_id}; applicable_when: inding_type in [UnauthorizedAccess, UnauthorizedAPI] and evidence_confidence > 0.7
   - 
evoke_security_group_ingress: allowed_params: {group_id, cidr, port}; applicable_when: cidr in [0.0.0.0/0, ::/0] and port > 1024
   - lock_s3_public_access: allowed_params: {bucket_name}; applicable_when: inding_type=PublicS3Bucket
   - isolate_ec2_instance: allowed_params: {instance_id}; applicable_when: inding_type=CompromisedEC2
   - enable_cloudtrail_logging: allowed_params: {trail_name}; applicable_when: inding_type=CloudTrailTampering
   - detach_privilege_escalation_policy: allowed_params: {role_arn, policy_arn}; applicable_when: inding_type=IAMPrivilegeEscalation
2. Each action has level: 1 (automatic), 2 (approval required), 3 (recommendation only)
3. Level assignments (default):
   - disable_iam_key: Level 2 (approval required — could lock out legitimate user)
   - 
evoke_security_group_ingress: Level 2
   - lock_s3_public_access: Level 1 (automatic — reversible)
   - isolate_ec2_instance: Level 2
   - enable_cloudtrail_logging: Level 1 (automatic — safety improvement)
   - detach_privilege_escalation_policy: Level 2
4. Policy stored in S3 (versioned) and loaded into SSM Parameter Store at deploy time
5. Policy includes last_reviewed timestamp and 
eviewer field

**Tests Required:** Unit tests for: policy JSON is valid, all actions have required fields, level values are valid (1-3), applicable_when conditions are parseable

**Expected Cost Impact:** 

**Manual Verification:** Review pproved-action-policy.json; confirm all 6 actions defined with levels and conditions; confirm policy passes JSON schema validation

---

### Task T09-02: Implement Schema Validation Stage

**Objective:** Build the first stage of the safety validation chain that validates the Bedrock recommendation against the investigation report schema.

**Files/Components Affected:** lambda/safety/schema_stage.py, 	ests/unit/test_schema_stage.py

**AWS Services Involved:** None

**Requirements Satisfied:** R9 (schema validation stage)

**Dependencies:** T06-03, T09-01

**Security Considerations:** ⚠️[SECURITY-RISK] Any recommendation that fails schema validation is automatically Level 3 (recommendation only) — it cannot proceed further.

**Acceptance Criteria:**
1. alidate_schema(recommendation) checks:
   - ction field is a string and exists
   - ction value matches one of the actions defined in approved-action-policy
   - params field is an object
   - params contains only keys allowed for that action
   - confidence field is a number between 0.0 and 1.0
   - 
ationale field is a string with maxLength 1000
2. On failure: return ValidationResult(level=3, reason=\"schema_invalid\", details=[...])
3. On success: pass to next stage (evidence validation)
4. Schema validation is the FIRST check — no further stages run if this fails

**Tests Required:** Unit tests for: valid recommendation passes, missing action fails, unknown action fails, invalid param types fail, confidence out of range fails, empty rationale fails

**Expected Cost Impact:** 

**Manual Verification:** Run unit tests; test with a malformed recommendation; confirm level=3 returned

---

### Task T09-03: Implement Evidence Validation Stage

**Objective:** Build the second stage that validates recommendation params against the investigation report's evidence.

**Files/Components Affected:** lambda/safety/evidence_stage.py, 	ests/unit/test_evidence_stage.py

**AWS Services Involved:** DynamoDB

**Requirements Satisfied:** R9 (evidence validation stage)

**Dependencies:** T06-04 (investigation report stored), T09-02

**Security Considerations:** ⚠️[SECURITY-RISK] Evidence validation prevents the platform from acting on AI hallucinations — every parameter in a recommendation must be traceable to actual evidence.

**Acceptance Criteria:**
1. alidate_evidence(recommendation, investigation_report) checks:
   - user_name param appears in ffected_principals of investigation report
   - ccess_key_id param appears in evidence citations
   - ucket_name param appears in ffected_resources of investigation report
   - group_id param appears in evidence citations
   - instance_id param appears in ffected_resources of investigation report
   - 
ole_arn param appears in ffected_principals of investigation report
2. On failure: return ValidationResult(level=3, reason=\"evidence_invalid\", details=[\"param X not found in evidence\"])
3. On success: pass to next stage (policy validation)

**Tests Required:** Unit tests for: param found in evidence passes, param not in evidence fails, multiple params validated, empty investigation report fails

**Expected Cost Impact:** 

**Manual Verification:** Test with a recommendation referencing a bucket in the report vs one not in the report

---

### Task T09-04: Implement Policy Validation and Risk Classification Stage

**Objective:** Build the third stage that checks the recommendation against the approved action policy and classifies risk level.

**Files/Components Affected:** lambda/safety/policy_stage.py, lambda/safety/risk_classifier.py, 	ests/unit/test_policy_stage.py, 	ests/unit/test_risk_classifier.py

**AWS Services Involved:** DynamoDB, IAM

**Requirements Satisfied:** R9 (policy validation, risk classification, Level 3→2→1 precedence)

**Dependencies:** T09-01, T09-02, T09-03

**Security Considerations:** ⚠️[SECURITY-RISK] This is the final deterministic gate. If the recommendation does not match any approved action policy entry, it is automatically Level 3. Risk classification overrides the policy level upward (never downward): high risk actions that are Level 1 are promoted to Level 2.

**Acceptance Criteria:**
1. alidate_policy(recommendation, policy) checks:
   - Action exists in policy
   - All params are within allowed_param_types
   - pplicable_when condition evaluates to true against investigation report
2. Risk classification rules (override level upward):
   - Blast radius risk_score >= 8.0 → minimum Level 2
   - Action affects a critical resource → minimum Level 2
   - Cross-account action → minimum Level 2
   - Night-time action (22:00-06:00 UTC) → minimum Level 2
3. Final level determination:
   - If schema validation failed → Level 3
   - If evidence validation failed → Level 3
   - If policy validation failed → Level 3
   - If risk classification overrides → max(policy_level, risk_override_level)
   - Otherwise → policy_level
4. Return: ValidationResult(level=1|2|3, reason, policy_entry, risk_factors, execution_decision)

**Tests Required:** Unit tests for: all 6 actions at correct levels, policy condition true/false, risk override scenarios (high blast radius, critical resource, night-time, cross-account), Level 3 from each failure stage

**Expected Cost Impact:** 

**Manual Verification:** Test each action type; confirm lock_s3_public_access gets Level 1, disable_iam_key gets Level 2, unknown action gets Level 3

---

### Task T09-05: Implement Execution Decision Engine

**Objective:** Build the orchestrator that runs all validation stages in sequence and produces the final execution decision.

**Files/Components Affected:** lambda/safety/execution_engine.py, lambda/safety/decision_store.py, 	ests/unit/test_execution_engine.py, 	ests/integration/test_safety_validation.py

**AWS Services Involved:** DynamoDB, EventBridge, SNS

**Requirements Satisfied:** R9 (full validation chain, execution decision)

**Dependencies:** T09-02, T09-03, T09-04

**Security Considerations:** ⚠️[SECURITY-RISK] The execution engine MUST never invoke a remediation Lambda directly. It only produces a decision. Remediation is triggered by separate Step Functions based on the decision.

**Acceptance Criteria:**
1. execute_validation(investigation_report) runs stages in order: schema → evidence → policy → risk classification
2. If ANY stage fails, remaining stages are skipped and Level 3 is returned
3. Decision stored in DynamoDB: decision_id, incident_id, ction, level, 
eason, 
isk_factors, created_at, expires_at (24h for Level 2)
4. Events published:
   - Level 1 → RemediationApproved event (triggers Step Functions)
   - Level 2 → RemediationApprovalRequired event (triggers human approval)
   - Level 3 → RemediationRejected event (logged only)
5. Decision audit trail: every validation stage result stored with timestamps
6. Integration test covers: Level 1 action approved, Level 2 action routed to approval, Level 3 action rejected

**Tests Required:** 5 unit tests (one per stage failure path + success); 1 integration test with full chain

**Expected Cost Impact:** 

**Manual Verification:** Invoke with a test investigation report; confirm Level 1 decision published as RemediationApproved; confirm Level 2 decision has expiry timestamp

**CHECKPOINT — Phase 9 Review:** Before proceeding to Phase 10, manually verify: (1) lock_s3_public_access with valid evidence gets Level 1, (2) disable_iam_key gets Level 2, (3) unknown action gets Level 3, (4) evidence not in report gets Level 3, (5) decision is stored in DynamoDB with expiry, (6) correct event type is published for each level.


---

## Phase 10: Remediation Framework

**Goal:** Build the generic remediation execution framework using Step Functions with idempotency, tracking, audit logging, failure handling, rollback, and verification hooks — before implementing any specific playbook.

**Danger Flags in this phase:** 🟣[AUTO-REMEDIATION] (enables automated remediation execution), 🟠[IAM-CHANGE] (Step Functions roles), 🟡[CHARGES] (Step Functions executions)

### Task T10-01: Deploy Remediation Step Functions State Machine

**Objective:** Create the generic Step Functions state machine that executes remediation playbooks with error handling and state tracking.

**Files/Components Affected:** 	erraform/modules/stepfunctions/remediation-machine.tf, lambda/remediation/state_machine_input.py, 	ests/unit/test_state_machine_input.py

**AWS Services Involved:** Step Functions, Lambda, DynamoDB, EventBridge

**Requirements Satisfied:** R10 (Step Functions, execution tracking, failure handling)

**Dependencies:** T09-05 (execution decisions), T02-06 (incident state machine)

**Security Considerations:** 🟣[AUTO-REMEDIATION] State machine role has permissions to invoke all remediation Lambda functions. Each Lambda has scoped permissions for its specific action. State machine never has direct AWS service permissions — only Lambda invocation.

**Acceptance Criteria:**
1. ASL state machine cloudsec-{env}-remediation-executor with states:
   - ReceiveDecision: input validation, decision expiry check
   - LockIncident: DynamoDB optimistic lock on incident record
   - ExecutePlaybook: map state or parallel state invoking the specific remediation Lambda
   - HandlePlaybookResult: success/failure branching
   - OnSuccess: emit RemediationExecuted event, transition incident to VERIFYING
   - OnFailure: emit RemediationFailed event, transition incident to ESCALATED
   - UnlockIncident: release DynamoDB lock
2. State machine IAM role has only lambda:InvokeFunction for remediation Lambdas + DynamoDB GetItem/UpdateItem on incidents table
3. Retry configured on ExecutePlaybook: max 2 retries, exponential backoff
4. Catch configured for all states with errors routed to OnFailure
5. Execution timeout: 5 minutes maximum
6. Input schema validation at ReceiveDecision rejects malformed inputs

**Tests Required:** pytest with ws-sam-local or manual ASL validation; unit tests for input schema validation; confirm state machine definition is valid ASL

**Expected Cost Impact:** 🟡[CHARGES] Step Functions ~.000025/1000 state transitions (negligible)

**Manual Verification:** Deploy state machine; manually start execution with test input; confirm it reaches OnSuccess or OnFailure state

---

### Task T10-02: Implement Idempotency Mechanism

**Objective:** Build the idempotency layer that prevents duplicate remediation execution for the same incident.

**Files/Components Affected:** lambda/common/idempotency.py, 	erraform/modules/dynamodb/idempotency-table.tf

**AWS Services Involved:** DynamoDB

**Requirements Satisfied:** R10 (idempotency)

**Dependencies:** T10-01

**Security Considerations:** Idempotency prevents accidental double-execution which could cause resource damage (e.g., disabling IAM keys twice). Uses DynamoDB with TTL for automatic cleanup.

**Acceptance Criteria:**
1. DynamoDB table cloudsec-{env}-idempotency with partition key idempotency_key (String) and sort key ction (String)
2. cquire_lock(idempotency_key, action) uses DynamoDB PutItem with ConditionExpression ttribute_not_exists(idempotency_key) AND attribute_not_exists(action)
3. 
elease_lock(idempotency_key, action) deletes the item
4. Lock TTL: 30 minutes (auto-expire stale locks)
5. If lock acquisition fails (another execution in progress), return IdempotencyConflict with existing execution_id
6. Idempotency key format: incident_id:action:principal_arn

**Tests Required:** Unit tests (moto) for: first call acquires lock, second call returns conflict, lock expiry, release and re-acquire

**Expected Cost Impact:** 🟡[CHARGES] ~/month (DynamoDB minimal)

**Manual Verification:** Deploy table; attempt two concurrent lock acquisitions with same key; confirm second fails

---

### Task T10-03: Implement Execution Tracking and Audit Logging

**Objective:** Build the audit trail that records every remediation execution attempt with full context.

**Files/Components Affected:** 	erraform/modules/dynamodb/remediation-audit-table.tf, lambda/common/audit_logger.py, 	ests/unit/test_audit_logger.py

**AWS Services Involved:** DynamoDB, CloudWatch

**Requirements Satisfied:** R10 (audit logging, execution tracking)

**Dependencies:** T10-01

**Security Considerations:** Audit log is append-only — no updates or deletes allowed after creation. Encrypted with KMS. This is the forensic record for every automated action.

**Acceptance Criteria:**
1. Table cloudsec-{env}-remediation-audit with partition key execution_id (String) and sort key event_time (String, ISO 8601)
2. log_execution_event(execution_id, event) writes a new item:
   - event_time (UTC ISO 8601)
   - execution_id (UUID)
   - incident_id
   - ction (remediation action name)
   - stage (STARTED, LOCK_ACQUIRED, PLAYBOOK_INVOKED, PLAYBOOK_SUCCEEDED, PLAYBOOK_FAILED, VERIFICATION_STARTED, VERIFICATION_PASSED, VERIFICATION_FAILED, COMPLETED, ESCALATED)
   - details (JSON object with stage-specific data)
   - ctor (ARN of the entity that triggered execution)
3. IAM policy on table allows only PutItem (no UpdateItem, DeleteItem)
4. CloudWatch structured log group cloudsec/{env}/remediation-audit receives duplicate logs for real-time visibility
5. Audit records retained for minimum 365 days (TTL configured for 400 days)

**Tests Required:** Unit tests for: event logging, stage progression, actor ARN capture, audit table write-only policy

**Expected Cost Impact:** 🟡[CHARGES] ~/month at dev scale

**Manual Verification:** Deploy table; invoke test execution; confirm audit table has records for each stage; confirm UpdateItem is denied

---

### Task T10-04: Implement Failure Handling and Rollback Strategy

**Objective:** Build the failure recovery mechanisms that attempt rollback when a remediation fails partway through.

**Files/Components Affected:** lambda/remediation/failure_handler.py, lambda/remediation/rollback_registry.py, 	ests/unit/test_failure_handler.py, 	ests/unit/test_rollback_registry.py

**AWS Services Involved:** DynamoDB, EventBridge, SNS

**Requirements Satisfied:** R10 (failure handling, rollback where possible)

**Dependencies:** T10-01

**Security Considerations:** Rollback is attempted only for actions where rollback is safe and well-defined. For irreversible actions (e.g., key deletion), rollback is not attempted and the incident is escalated.

**Acceptance Criteria:**
1. 
ollback_registry maps each action to its rollback function:
   - lock_s3_public_access → 
evert_s3_public_access_block (re-applies previous policy)
   - disable_iam_key → 
e-enable IAM key (only if key was not fully deleted)
   - 
evoke_security_group_ingress → 
e-add security group ingress rule
   - isolate_ec2_instance → 
e-attach original security group
   - enable_cloudtrail_logging → N/A (no rollback needed, it's additive)
   - detach_privilege_escalation_policy → 
e-attach policy
2. Before executing any action, the current state is saved to DynamoDB (pre_remediation_state) for rollback reference
3. On failure, execute_rollback(action, pre_state) is called
4. If rollback also fails: incident is escalated with escalation_reason=rollback_failed
5. Rollback execution is logged to audit table with stage=ROLLBACK_*

**Tests Required:** Unit tests for: each action has rollback handler, rollback saves and restores state, irreversible action has no rollback, rollback failure escalation

**Expected Cost Impact:** 

**Manual Verification:** Unit tests; manually trigger a failed remediation; confirm rollback is attempted and logged

---

### Task T10-05: Implement Verification Hooks

**Objective:** Build the hooks that the remediation framework calls before and after each playbook execution to verify state.

**Files/Components Affected:** lambda/remediation/verification_hooks.py, 	ests/unit/test_verification_hooks.py

**AWS Services Involved:** DynamoDB, EventBridge

**Requirements Satisfied:** R10 (verification hooks), R13 (pre-remediation state capture)

**Dependencies:** T10-03

**Security Considerations:** Verification hooks are called BEFORE and AFTER each remediation step. Pre-hooks capture the "before" state; post-hooks validate the "after" state. If a pre-hook fails, execution is stopped before any change is made.

**Acceptance Criteria:**
1. pre_execution_hook(action, params) validates:
   - Incident is in status REMEDIATING
   - Decision is still valid (not expired)
   - Resource still exists in AWS
   - Current state matches expected vulnerable state
2. post_execution_hook(action, params, result) validates:
   - Resource exists (was not deleted accidentally)
   - Expected secure state is observable (e.g., S3 public access block is applied)
   - No unexpected side effects (e.g., other resources not modified)
3. Hook results logged to audit table
4. Pre-hook failure → execution stopped, incident transitioned to ESCALATED
5. Post-hook failure → rollback triggered (T10-04)

**Tests Required:** Unit tests for: pre-hook passes (valid state), pre-hook fails (incident not in REMEDIATING), post-hook passes (secure state verified), post-hook fails (state not changed)

**Expected Cost Impact:** 

**Manual Verification:** Run unit tests; manually verify pre-hook blocks execution when incident is in wrong status


---

## Phase 11: Remediation Playbooks

**Goal:** Implement each remediation playbook separately and test it before proceeding to the next. Do NOT implement all six simultaneously.

**Danger Flags in this phase:** 🟣[AUTO-REMEDIATION] (all playbooks execute state-changing AWS operations), 🟠[IAM-CHANGE] (IAM modifications in playbooks 1, 6), ⚠️[SECURITY-RISK] (incorrect implementation could cause service disruption)

### Task T11-01: Playbook 1 — Compromised IAM Credential

**Objective:** Build the remediation playbook that disables a compromised IAM access key.

**Files/Components Affected:** lambda/remediation/playbooks/disable_iam_key.py, 	ests/unit/test_disable_iam_key.py, 	ests/integration/test_disable_iam_key.py

**AWS Services Involved:** IAM, DynamoDB, EventBridge, CloudWatch

**Requirements Satisfied:** R11 (Compromised IAM Credential playbook)

**Dependencies:** T10-01, T10-02, T10-03, T10-04, T10-05

**Security Considerations:** 🟣[AUTO-REMEDIATION] 🟠[IAM-CHANGE] Lambda role needs iam:UpdateAccessKey (not DeleteAccessKey). Key is disabled (Status=Inactive), not deleted, to preserve audit trail and allow re-enable. Playbook only executes if Safety Validation Engine returned Level 1 or Level 2 with approved decision.

**Acceptance Criteria:**
1. disable_key(user_name, access_key_id) calls iam.update_access_key(Status=Inactive)
2. Pre-execution hook verifies:
   - Key exists and is currently Active
   - Key is associated with the compromised principal from the investigation report
   - Key was used in the suspicious activity (CloudTrail check)
3. Post-execution hook verifies:
   - Key Status is now Inactive
   - Key can no longer be used for API calls (test with TestAccessKey)
4. Pre-state saved: key Status, user name, last used timestamp
5. On failure: rollback re-enables the key (Status=Active)
6. Idempotency: if key is already Inactive, playbook returns success without change
7. Audit event logged with key_id, user_name, previous_status, new_status
8. Integration test: create test IAM user with key, invoke playbook, confirm key disabled

**Tests Required:** 6 unit tests (key exists active, key already inactive, key not found, IAM error, rollback on failure, idempotency); 1 integration test with real IAM (dev account only)

**Expected Cost Impact:** 🟡[CHARGES] Lambda invocation negligible

**Manual Verification:** Create test IAM user + key in dev account; simulate GuardDuty finding; run playbook via Step Functions; confirm key is Inactive; confirm audit trail

---

### Task T11-02: Playbook 2 — Dangerous Security Group Change

**Objective:** Build the remediation playbook that revokes overly permissive security group ingress rules.

**Files/Components Affected:** lambda/remediation/playbooks/revoke_sg_ingress.py, 	ests/unit/test_revoke_sg_ingress.py, 	ests/integration/test_revoke_sg_ingress.py

**AWS Services Involved:** EC2, DynamoDB, EventBridge

**Requirements Satisfied:** R11 (Dangerous Security Group Change playbook)

**Dependencies:** T11-01

**Security Considerations:** 🟣[AUTO-REMEDIATION] ⚠️[SECURITY-RISK] Revoking a security group rule could disrupt legitimate traffic. Pre-execution hook must confirm the rule is the one that was modified by the suspicious activity, not a pre-existing legitimate rule.

**Acceptance Criteria:**
1. 
evoke_ingress(group_id, cidr, from_port, to_port, protocol) calls ec2.revoke_security_group_ingress()
2. Pre-execution hook verifies:
   - Security group exists
   - Rule matches the one identified in the investigation report
   - Rule was created/modified within the incident time window (not a pre-existing rule)
   - Rule allows ingress from  .0.0.0/0 or ::/0 (public)
3. Post-execution hook verifies:
   - Rule no longer appears in describe_security_group_rules
   - Security group still exists (was not deleted)
4. Pre-state saved: full rule details including group_id, cidr, port, protocol, rule_id
5. On failure: rollback re-adds the rule with uthorize_security_group_ingress
6. Idempotency: if rule is already revoked, return success without change
7. Only rules matching the investigation evidence are revoked — no broad cleanup

**Tests Required:** 6 unit tests (rule exists, rule not found, rule pre-existing, EC2 error, rollback, idempotency); 1 integration test with real SG (dev account)

**Expected Cost Impact:** 🟡[CHARGES] Lambda invocation negligible

**Manual Verification:** Create test SG with 0.0.0.0/0 rule; simulate finding; run playbook; confirm rule revoked; confirm rollback restores it

---

### Task T11-03: Playbook 3 — Public S3 Exposure

**Objective:** Build the remediation playbook that applies S3 Block Public Access settings to a publicly exposed bucket.

**Files/Components Affected:** lambda/remediation/playbooks/block_s3_public_access.py, 	ests/unit/test_block_s3_public_access.py, 	ests/integration/test_block_s3_public_access.py

**AWS Services Involved:** S3, DynamoDB, EventBridge

**Requirements Satisfied:** R11 (Public S3 Exposure playbook)

**Dependencies:** T11-02

**Security Considerations:** 🟣[AUTO-REMEDIATION] This is the safest automated action (Level 1) — blocking public access is always correct for a bucket identified as publicly exposed. However, pre-execution hook must confirm the bucket was not intentionally public (check intentional_public tag).

**Acceptance Criteria:**
1. lock_public_access(bucket_name) calls s3.put_public_access_block(Bucket=bucket_name, PublicAccessBlockConfiguration={BlockPublicAcls: True, IgnorePublicAcls: True, BlockPublicPolicy: True, RestrictPublicBuckets: True})
2. Pre-execution hook verifies:
   - Bucket exists
   - Bucket is identified as publicly exposed in investigation report
   - Bucket does NOT have tag intentional_public=true (if it does, escalate instead)
3. Post-execution hook verifies:
   - get_public_access_block returns all four blocks set to True
   - Bucket is still accessible for private API calls (not deleted)
4. Pre-state saved: previous public access block configuration
5. On failure: rollback re-applies previous configuration
6. Idempotency: if all blocks are already True, return success

**Tests Required:** 6 unit tests (bucket exists, bucket not found, intentional_public tag, S3 error, rollback, idempotency); 1 integration test (dev account)

**Expected Cost Impact:** 🟡[CHARGES] Lambda invocation negligible

**Manual Verification:** Create test S3 bucket with public access; run playbook; confirm BlockPublicAccess enabled; verify rollback

---

### Task T11-04: Playbook 4 — Compromised EC2 Instance

**Objective:** Build the remediation playbook that isolates a compromised EC2 instance by detaching its security group and attaching an isolation group.

**Files/Components Affected:** lambda/remediation/playbooks/isolate_ec2.py, 	ests/unit/test_isolate_ec2.py, 	ests/integration/test_isolate_ec2.py

**AWS Services Involved:** EC2, DynamoDB, EventBridge, KMS

**Requirements Satisfied:** R11 (Compromised EC2 Instance playbook)

**Dependencies:** T11-03

**Security Considerations:** 🟣[AUTO-REMEDIATION] ⚠️[SECURITY-RISK] Isolating an EC2 instance will disrupt any running service. This is Level 2 (requires approval). Pre-execution hook must confirm the instance is tagged with the CloudSec AI isolation tag or explicitly approved. Rollback re-attaches the original security group.

**Acceptance Criteria:**
1. isolate_instance(instance_id) performs:
   - Create isolation security group cloudsec-{env}-isolation-sg (deny all inbound/outbound) in the same VPC
   - Detach instance from current security groups
   - Attach instance to isolation security group
   - Create snapshot of instance volume (for forensics) — ec2.create_snapshot(VolumeId=vol_id, Description=...)
2. Pre-execution hook verifies:
   - Instance exists and is running
   - Instance is identified in investigation report
   - Instance is not tagged cloudsec_no_isolate=true
3. Post-execution hook verifies:
   - Instance has only the isolation SG attached
   - Snapshot is creating (state=pending or completing)
4. Pre-state saved: instance security groups, volume IDs, instance state
5. On failure: rollback re-attaches original security groups
6. Isolation SG created once and reused (idempotent SG creation)
7. Instance state transitioned to VERIFYING after isolation

**Tests Required:** 6 unit tests (instance exists, instance stopped, no_isolate tag, EC2 error, rollback, snapshot failure); 1 integration test (dev account, create and terminate test instance)

**Expected Cost Impact:** 🟡[CHARGES] 🟡[CHARGES] Snapshot storage ~.05/GB/month; Lambda invocation negligible

**Manual Verification:** Launch test EC2 in dev; simulate finding; run playbook with approved decision; confirm instance isolated (no SG except isolation); confirm snapshot created

---

### Task T11-05: Playbook 5 — CloudTrail Tampering

**Objective:** Build the remediation playbook that detects and responds to CloudTrail tampering by re-enabling logging and creating a new trail if needed.

**Files/Components Affected:** lambda/remediation/playbooks/fix_cloudtrail.py, 	ests/unit/test_fix_cloudtrail.py, 	ests/integration/test_fix_cloudtrail.py

**AWS Services Involved:** CloudTrail, DynamoDB, EventBridge, KMS

**Requirements Satisfied:** R11 (CloudTrail Tampering playbook)

**Dependencies:** T11-04

**Security Considerations:** 🟣[AUTO-REMEDIATION] 🟠[IAM-CHANGE] This is a Level 1 action (automatic) — re-enabling CloudTrail is always a safety improvement. New trail created with same configuration as original.

**Acceptance Criteria:**
1. ix_cloudtrail(trail_name) performs:
   - Check if trail exists
   - If trail exists but logging disabled: call start_logging()
   - If trail was deleted: create new trail with same configuration (multi-region, org trail, same S3 bucket, same KMS key)
   - Enable log file validation on the trail
2. Pre-execution hook verifies:
   - Trail name matches investigation report
   - Trail exists OR was recently deleted (within 24 hours based on CloudTrail event)
3. Post-execution hook verifies:
   - Trail is logging (is_logging=true)
   - Log file validation is enabled
   - Trail delivers to correct S3 bucket
4. Pre-state saved: trail logging state, validation state
5. No rollback needed (action is additive — re-enabling logging)
6. If trail was deleted, new trail name suffixed with -recreated-{timestamp}

**Tests Required:** 5 unit tests (trail exists logging disabled, trail exists logging enabled, trail deleted, CloudTrail error, post-verification); 1 integration test (dev account, create and stop logging on test trail)

**Expected Cost Impact:** 🟡[CHARGES] Lambda invocation negligible; new trail cost same as original

**Manual Verification:** Create test trail in dev; disable logging; run playbook; confirm logging re-enabled

---

### Task T11-06: Playbook 6 — IAM Privilege Escalation

**Objective:** Build the remediation playbook that removes a suspiciously attached IAM policy from a role.

**Files/Components Affected:** lambda/remediation/playbooks/detach_privilege_policy.py, 	ests/unit/test_detach_privilege_policy.py, 	ests/integration/test_detach_privilege_policy.py

**AWS Services Involved:** IAM, DynamoDB, EventBridge

**Requirements Satisfied:** R11 (IAM Privilege Escalation playbook)

**Dependencies:** T11-05

**Security Considerations:** 🟣[AUTO-REMEDIATION] 🟠[IAM-CHANGE] ⚠️[SECURITY-RISK] Detaching a policy could remove legitimate permissions. This is Level 2 (requires approval). Pre-execution hook must confirm the policy was attached within the incident time window (not a pre-existing policy).

**Acceptance Criteria:**
1. detach_policy(role_arn, policy_arn) calls iam.detach_role_policy()
2. Pre-execution hook verifies:
   - Role exists
   - Policy is currently attached to role
   - Policy was attached within the incident time window (based on CloudTrail AttachRolePolicy event)
   - Policy ARN is in the investigation report's ffected_resources
3. Post-execution hook verifies:
   - Policy is no longer attached (list_attached_role_policies confirms)
   - Role still exists (was not deleted)
4. Pre-state saved: all policies attached to role before detachment
5. On failure: rollback re-attaches the policy
6. Idempotency: if policy is not attached, return success without change
7. Policy ARN is logged in audit trail for forensic review

**Tests Required:** 6 unit tests (policy attached, policy not attached, pre-existing policy, IAM error, rollback, idempotency); 1 integration test (dev account)

**Expected Cost Impact:** 🟡[CHARGES] Lambda invocation negligible

**Manual Verification:** Create test role and attach a test policy in dev; simulate finding; run playbook with approved decision; confirm policy detached; confirm rollback restores it


---

## Phase 12: Human Approval

**Goal:** Build the human-in-the-loop approval API that handles Level 2 execution decisions — the gateway between AI recommendation and automated execution for high-risk actions.

**Danger Flags in this phase:** 🔵[HUMAN-APPROVAL] (this is the human approval layer), ⚠️[SECURITY-RISK] (self-approval prevention, auth/authz), 🟡[CHARGES] (API Gateway, Cognito)

### Task T12-01: Deploy Approval API (API Gateway + Lambda)

**Objective:** Create a REST API for reviewing and responding to pending approval requests.

**Files/Components Affected:** 	erraform/modules/apigateway/approval-api.tf, lambda/approval/approval_handler.py, 	ests/unit/test_approval_handler.py

**AWS Services Involved:** API Gateway, Lambda, Cognito, DynamoDB, Step Functions

**Requirements Satisfied:** R12 (approval API, authentication/authorization)

**Dependencies:** T09-05 (Level 2 decisions), T10-01 (Step Functions)

**Security Considerations:** 🔵[HUMAN-APPROVAL] API requires Cognito user pool authentication. Only users with cloudsec_approver group can approve or reject. API uses HTTPS only. All requests logged to CloudTrail.

**Acceptance Criteria:**
1. API Gateway REST API cloudsec-{env}-approval-api with endpoints:
   - POST /decisions/{decision_id}/approve — approve a Level 2 decision
   - POST /decisions/{decision_id}/reject — reject a Level 2 decision
   - GET /decisions/pending — list all pending approvals (paginated)
   - GET /decisions/{decision_id} — get decision details
2. Cognito User Pool cloudsec-{env}-user-pool with groups: cloudsec_approver, cloudsec_viewer
3. IAM Authorizer on API Gateway validates Cognito token and checks group membership
4. Only cloudsec_approver group can POST approve/reject
5. Only cloudsec_viewer and cloudsec_approver can GET decisions
6. Lambda cloudsec-{env}-approval-handler processes API requests
7. API Gateway access logging enabled to S3

**Tests Required:** Unit tests for: valid approve request, valid reject request, unauthorized user, expired decision, invalid decision_id, pagination

**Expected Cost Impact:** 🟡[CHARGES] API Gateway ~.00/1M requests; Cognito User Pool ~.000007/auth; negligible dev usage

**Manual Verification:** Deploy API; create Cognito user in approver group; call approve endpoint with valid token; confirm decision status updated

---

### Task T12-02: Implement Approval Expiration and Decision Management

**Objective:** Build the decision lifecycle management including expiration, pending state tracking, and expiry notifications.

**Files/Components Affected:** lambda/approval/decision_manager.py, 	erraform/modules/dynamodb/approval-decisions-table.tf, 	ests/unit/test_decision_manager.py

**AWS Services Involved:** DynamoDB, EventBridge, SNS

**Requirements Satisfied:** R12 (expiration, pending state)

**Dependencies:** T12-01

**Security Considerations:** Decisions expire after 24 hours to prevent stale approvals being used later. Expired decisions are automatically escalated. Expiration is checked on every approval attempt.

**Acceptance Criteria:**
1. Table cloudsec-{env}-approval-decisions with partition key decision_id (String) and sort key created_at (String, ISO 8601)
2. Decision record fields: decision_id, incident_id, ction, params, evidence_summary, 
isk_score, created_at, expires_at, status (PENDING, APPROVED, REJECTED, EXPIRED), pproved_by (ARN), pproved_at, 
ejection_reason
3. create_pending_decision() creates record with expires_at = created_at + 24 hours
4. pprove_decision(decision_id, approver_arn) checks:
   - Decision exists and status is PENDING
   - Decision has not expired
   - Approver is not the same principal as the compromised identity (self-approval prevention)
   - On pass: status set to APPROVED, approved_by and approved_at recorded
5. 
eject_decision(decision_id, approver_arn, reason) sets status to REJECTED
6. EventBridge scheduled rule pproval-expiry-check runs every 5 minutes: scans for expired PENDING decisions, transitions to EXPIRED, escalates incident

**Tests Required:** Unit tests for: create decision, approve valid decision, approve expired decision, approve by self (denied), reject decision, expiry check, double-approve prevention

**Expected Cost Impact:** 🟡[CHARGES] ~/month (DynamoDB + EventBridge schedule)

**Manual Verification:** Create pending decision; wait for expiry (or manually set expiry to past); confirm scheduled rule escalates it

---

### Task T12-03: Implement Self-Approval Prevention and Audit Trail

**Objective:** Build the controls that prevent the compromised principal (or anyone acting on their behalf) from approving their own remediation.

**Files/Components Affected:** lambda/approval/self_approval_checker.py, 	ests/unit/test_self_approval_checker.py

**AWS Services Involved:** DynamoDB, IAM

**Requirements Satisfied:** R12 (self-approval prevention, audit trail, duplicate-decision prevention)

**Dependencies:** T12-02

**Security Considerations:** ⚠️[SECURITY-RISK] Self-approval is a critical bypass — if the compromised principal can approve their own remediation (or lack thereof), the entire safety model is defeated.

**Acceptance Criteria:**
1. check_self_approval(decision, approver_arn) compares:
   - pprover_arn against all ffected_principals in the investigation report
   - pprover_arn against all principals in the incident's findings
   - If the approver is in the affected principals list → DENY with reason self_approval_attempted
2. Role chain resolution: if approver assumed a role, the original principal is also checked
3. Duplicate decision prevention: if the same decision_id has already been APPROVED or REJECTED, any subsequent attempt is rejected
4. Audit event logged for every self-approval attempt with approver ARN, decision ID, and affected principals
5. Self-approval attempts trigger a CloudWatch alarm SuspiciousApprovalAttempt after 3 attempts in 1 hour

**Tests Required:** Unit tests for: approver is affected principal (denied), approver is unrelated (allowed), role chain resolution, duplicate decision rejected, audit event logged

**Expected Cost Impact:** 

**Manual Verification:** Unit tests; manually attempt approval with compromised principal's ARN; confirm denied and audit event logged

---

### Task T12-04: Implement Step Functions Callback Integration

**Objective:** Build the integration that resumes the Step Functions remediation workflow when a human approval decision is received.

**Files/Components Affected:** lambda/approval/stepfunctions_callback.py, 	ests/unit/test_stepfunctions_callback.py

**AWS Services Involved:** Step Functions, DynamoDB, EventBridge

**Requirements Satisfied:** R12 (Step Functions callback)

**Dependencies:** T12-02, T10-01

**Security Considerations:** Step Functions callback token is a sensitive credential — it is only exposed through the approval API after authentication. Token is time-limited (matches decision expiry).

**Acceptance Criteria:**
1. When a Level 2 decision is created, Step Functions enters a WaitForApproval state with a callback URL
2. pprove_decision() and 
eject_decision() call SendTaskSuccess or SendTaskFailed to resume the Step Functions execution
3. Callback payload includes: decision_id, pproved_by, pproved_at (for approve) or 
ejection_reason (for reject)
4. If decision expires while Step Functions is waiting: Step Functions receives timeout → incident escalated
5. Callback token is stored in DynamoDB approval decisions table with callback_url
6. Step Functions WaitForApproval state has timeout matching decision expiry (24 hours minus 1 hour buffer)
7. On Step Functions callback timeout: emit RemediationApprovalTimedOut event, transition incident to ESCALATED

**Tests Required:** Unit tests (mocked Step Functions) for: approval callback resumes execution, rejection callback sends failure, timeout escalation, callback with expired token denied

**Expected Cost Impact:** 🟡[CHARGES] Step Functions wait state ~.000001/hour (negligible)

**Manual Verification:** Deploy Step Functions with WaitForApproval state; create Level 2 decision; confirm Step Functions pauses; approve via API; confirm Step Functions resumes


---

## Phase 13: Verification Engine

**Goal:** Build the verification engine that re-queries AWS state after every remediation to confirm the expected secure state was achieved — and either RESOLVES or ESCALATES the incident.

**Danger Flags in this phase:** 🟡[CHARGES] (AWS API calls for verification), ⚠️[SECURITY-RISK] (verification logic must be accurate to prevent false resolution)

**Manual Checkpoint:** End of Phase 13 — verify the engine correctly resolves a test remediation and escalates a failed one before proceeding to evidence preservation.

### Task T13-01: Implement Post-Remediation AWS State Re-Query

**Objective:** Build the verification logic that queries AWS APIs to confirm the current state of remediated resources.

**Files/Components Affected:** lambda/verification/state_checker.py, 	ests/unit/test_state_checker.py

**AWS Services Involved:** IAM, EC2, S3, CloudTrail, DynamoDB

**Requirements Satisfied:** R13 (re-query AWS state, validate expected secure state)

**Dependencies:** T11-01 through T11-06 (all playbooks), T10-05 (verification hooks)

**Security Considerations:** Verification uses read-only AWS API calls only. Verification role has iam:GetAccessKeyLastUsed, iam:GetAccessKeyStatus, ec2:DescribeSecurityGroups, s3:GetPublicAccessBlock, cloudtrail:GetTrailStatus — no write permissions.

**Acceptance Criteria:**
1. erify_iam_key_disabled(key_id) → checks iam.get_access_key_last_used() returns AccessDenied or key status is Inactive
2. erify_sg_ingress_revoked(group_id, cidr, port) → checks ec2.describe_security_group_rules() does not contain the rule
3. erify_s3_public_blocked(bucket_name) → checks s3.get_public_access_block() returns all four blocks True
4. erify_ec2_isolated(instance_id) → checks instance has only isolation SG attached; checks snapshot state
5. erify_cloudtrail_logging(trail_name) → checks cloudtrail.get_trail_status() returns is_logging=True and latest_delivery_time is recent
6. erify_policy_detached(role_arn, policy_arn) → checks iam.list_attached_role_policies() does not contain the policy
7. Each verifier returns: erified=True/False, ctual_state, expected_state, erification_time

**Tests Required:** Unit tests for each verifier: verified state passes, not-verified state fails, AWS error returns verification failure

**Expected Cost Impact:** 🟡[CHARGES] AWS API calls ~.0001/call (negligible)

**Manual Verification:** Run unit tests; manually invoke verifiers against known state; confirm correct True/False

---

### Task T13-02: Implement Finding Re-Check and Containment Confirmation

**Objective:** After remediation, re-check the original findings to confirm the threat is contained.

**Files/Components Affected:** lambda/verification/finding_rechecker.py, 	ests/unit/test_finding_rechecker.py

**AWS Services Involved:** GuardDuty, Security Hub, CloudTrail, DynamoDB

**Requirements Satisfied:** R13 (re-check relevant findings, confirm containment)

**Dependencies:** T13-01

**Security Considerations:** Re-checking must not trigger new findings. GuardDuty findings are re-evaluated by the service — we only check if the finding status changed to ARCHIVED. Security Hub findings are checked for resolution.

**Acceptance Criteria:**
1. 
echeck_findings(incident_id) for each finding in the incident:
   - GuardDuty: check if finding status is ARCHIVED (GuardDuty auto-archives after remediation)
   - Security Hub: check if finding has Compliance.Status=PASSED or RecordState=ARCHIVED
   - CloudTrail: check that the suspicious API action has not been repeated in the last 30 minutes
2. Containment confirmed if ALL findings in the incident are in a resolved/archived state
3. If ANY finding is still ACTIVE, containment is NOT confirmed
4. Results stored in DynamoDB incidents table under erification.containment
5. Containment check runs at 30-second and 5-minute intervals after remediation (two passes)

**Tests Required:** Unit tests for: all findings archived (contained), one finding active (not contained), GuardDuty finding status check, Security Hub finding status check, CloudTrail repeat action check

**Expected Cost Impact:** 🟡[CHARGES] API calls negligible

**Manual Verification:** Simulate a finding; run re-check; confirm containment status

---

### Task T13-03: Implement Resolve or Escalate Decision Logic

**Objective:** Build the final decision logic that RESOLVES or ESCALATES each incident based on verification results.

**Files/Components Affected:** lambda/verification/resolution_engine.py, 	ests/unit/test_resolution_engine.py

**AWS Services Involved:** DynamoDB, SNS, EventBridge

**Requirements Satisfied:** R13 (RESOLVE or ESCALATE, escalation notification within 30 seconds)

**Dependencies:** T13-01, T13-02

**Security Considerations:** ⚠️[SECURITY-RISK] False resolution (marking an incident resolved when the threat is not actually contained) is a critical failure. Resolution requires ALL verification checks to pass. Any single failure triggers escalation.

**Acceptance Criteria:**
1. 
esolve_or_escalate(incident_id) evaluates:
   - All state verifications passed (T13-01) → state_verified=True
   - All findings re-checked and contained (T13-02) → containment_confirmed=True
   - No new findings for this incident in the last 5 minutes → 
o_new_findings=True
2. RESOLVE if ALL three conditions are True:
   - Incident status → RESOLVED
   - 
esolved_at and 	ime_to_resolve_seconds recorded
   - IncidentResolved event published
3. ESCALATE if ANY condition is False:
   - Incident status → ESCALATED
   - SNS notification sent to cloudsec-{env}-escalations within 30 seconds
   - Notification includes: incident_id, severity, verification_failures, containment_status
   - IncidentEscalated event published
4. Verification results stored in DynamoDB with full detail for audit

**Tests Required:** Unit tests for: all pass → RESOLVED, state check fails → ESCALATED, containment fails → ESCALATED, new finding detected → ESCALATED, escalation notification sent within 30s

**Expected Cost Impact:** 🟡[CHARGES] SNS notification negligible

**Manual Verification:** Simulate successful remediation; confirm RESOLVED; simulate failed verification; confirm ESCALATED and SNS notification

---

### Task T13-04: Deploy Verification Lambda and EventBridge Trigger

**Objective:** Deploy the verification Lambda and wire it to be triggered automatically after remediation execution.

**Files/Components Affected:** 	erraform/modules/lambda/verification-lambda.tf, 	erraform/modules/eventbridge/verification-rule.tf

**AWS Services Involved:** Lambda, EventBridge, DynamoDB

**Requirements Satisfied:** R13 (automated verification after remediation)

**Dependencies:** T13-01, T13-02, T13-03, T02-03 (security bus)

**Security Considerations:** Verification Lambda runs with read-only AWS permissions plus DynamoDB write for results. Cannot perform any state-changing actions.

**Acceptance Criteria:**
1. Lambda cloudsec-{env}-verification-engine deployed with read-only IAM role
2. EventBridge rule 
emediation-executed on security bus matches detail-type=RemediationExecuted and targets verification Lambda
3. Verification Lambda runs the full verification chain: state check → finding re-check → resolve/escalate
4. Lambda timeout: 60 seconds, memory: 512 MB
5. Verification results stored in incidents table
6. Lambda has reserved concurrency of 3

**Tests Required:** Manual trigger of verification Lambda with test incident; confirm correct resolve/escalate decision

**Expected Cost Impact:** 🟡[CHARGES] Lambda invocation negligible

**Manual Verification:** Deploy; trigger remediation; confirm verification Lambda is automatically invoked by EventBridge rule; confirm incident reaches RESOLVED or ESCALATED

**CHECKPOINT — Phase 13 Review:** Before proceeding to Phase 14, manually verify: (1) successful remediation → RESOLVED, (2) failed verification → ESCALATED, (3) SNS escalation notification fires, (4) verification results stored in DynamoDB, (5) containment confirmed for contained threats, (6) new findings detected during verification triggers escalation.


---

## Phase 14: Evidence Preservation

**Goal:** Build the forensic evidence preservation system — encrypted, versioned S3 storage with manifests, configuration snapshots, remediation history, AI analysis storage, and verification results.

**Danger Flags in this phase:** 🔴[HARD-TO-DELETE] (S3 bucket with versioning + object-lock, KMS keys), 🟡[CHARGES] (S3 storage, KMS)

### Task T14-01: Deploy Evidence S3 Bucket with KMS Encryption and Versioning

**Objective:** Create the evidence bucket with all security controls for forensic preservation.

**Files/Components Affected:** 	erraform/modules/s3/evidence-bucket.tf

**AWS Services Involved:** S3, KMS

**Requirements Satisfied:** R14 (evidence S3 bucket, KMS, versioning, development-safe retention)

**Dependencies:** T01-06 (KMS keys)

**Security Considerations:** 🔴[HARD-TO-DELETE] S3 bucket with versioning and object-lock in GOVERNANCE mode. Object-lock retention period: 30 days in dev, 365 days in prod. Bucket is immutable — objects cannot be overwritten or deleted before retention expires.

**Acceptance Criteria:**
1. Bucket cloudsec-{env}-evidence-{account} created with:
   - Versioning enabled
   - Block public access (all four settings)
   - SSE-KMS with cloudsec-{env}-evidence-key
   - Object-lock enabled in GOVERNANCE mode
   - Retention period: 30 days (dev), 365 days (prod) — configurable via variable
   - Access logs delivered to a separate logging bucket
2. Bucket policy denies all non-platform access
3. Bucket policy requires x-amz-server-side-encryption header on all PutObject requests
4. Bucket tagging per naming standard
5. Lifecycle rule: transition noncurrent versions to Glacier after 90 days (dev: after 30 days)

**Tests Required:** ws s3api get-bucket-versioning; confirm ObjectLockConfiguration; attempt to upload without SSE header (should fail)

**Expected Cost Impact:** 🔴[HARD-TO-DELETE] 🟡[CHARGES] ~-5/month storage + KMS; object-lock prevents deletion until retention expires

**Manual Verification:** Upload test object; confirm encryption; attempt to delete (should fail or require bypass); confirm versioning works

---

### Task T14-02: Implement Evidence Manifest Generation

**Objective:** Build the Lambda that generates a cryptographic manifest for each incident's evidence package.

**Files/Components Affected:** lambda/evidence/manifest_generator.py, 	ests/unit/test_manifest_generator.py

**AWS Services Involved:** S3, DynamoDB

**Requirements Satisfied:** R14 (evidence manifests)

**Dependencies:** T14-01

**Security Considerations:** Manifest includes SHA-256 hash of every evidence file, enabling tamper detection. Manifest itself is written with object-lock retention.

**Acceptance Criteria:**
1. generate_manifest(incident_id) collects all evidence files for the incident and generates:
   - incident_id
   - manifest_version (1.0)
   - generated_at (UTC ISO 8601)
   - iles: array of {ile_name, sha256, size_bytes, s3_key}
   - overall_sha256 (hash of all individual hashes concatenated)
   - 	otal_files
   - 	otal_size_bytes
2. Manifest written to S3 as evidence/{incident_id}/manifest.json with object-lock retention
3. Manifest hash also stored in DynamoDB incidents table for quick verification
4. Manifest is the authoritative record of what evidence was preserved for an incident

**Tests Required:** Unit tests for: manifest generation with multiple files, SHA-256 correctness, overall hash computation

**Expected Cost Impact:** 🟡[CHARGES] Negligible (small JSON file)

**Manual Verification:** Upload test evidence files; generate manifest; verify SHA-256 of each file matches

---

### Task T14-03: Implement Configuration Snapshot Capture

**Objective:** Build the Lambda that captures the configuration state of remediated resources at the time of the incident.

**Files/Components Affected:** lambda/evidence/config_snapshot.py, 	ests/unit/test_config_snapshot.py

**AWS Services Involved:** IAM, EC2, S3, CloudTrail, DynamoDB, S3

**Requirements Satisfied:** R14 (configuration snapshots)

**Dependencies:** T14-01, T13-01

**Security Considerations:** Snapshot is taken BEFORE remediation (via pre-execution hook) and stored with object-lock. This preserves the pre-incident state for forensic comparison.

**Acceptance Criteria:**
1. capture_config_snapshot(incident_id) captures:
   - IAM users/roles involved: iam.get_user(), iam.get_role(), iam.list_attached_user_policies()
   - S3 bucket policies: s3.get_bucket_policy(), s3.get_public_access_block()
   - EC2 instance details: ec2.describe_instances()
   - Security group rules: ec2.describe_security_group_rules()
   - CloudTrail trail status: cloudtrail.get_trail_status()
2. All data captured in a single JSON document
3. Snapshot written to S3 as evidence/{incident_id}/pre_remediation_config.json
4. Snapshot taken as part of the pre-execution verification hook (T10-05)
5. Snapshot includes captured_at timestamp and capture_actor (Lambda ARN)

**Tests Required:** Unit tests (mocked AWS) for: IAM snapshot, S3 snapshot, EC2 snapshot, SG snapshot, CloudTrail snapshot, combined capture

**Expected Cost Impact:** 🟡[CHARGES] S3 storage negligible per incident

**Manual Verification:** Trigger test incident; confirm pre-remediation config snapshot written to S3

---

### Task T14-04: Implement Remediation History Storage

**Objective:** Build the storage mechanism for the complete remediation history of each incident.

**Files/Components Affected:** lambda/evidence/remediation_history.py, 	ests/unit/test_remediation_history.py

**AWS Services Involved:** DynamoDB, S3

**Requirements Satisfied:** R14 (remediation history)

**Dependencies:** T10-03 (audit logging), T14-01

**Security Considerations:** Remediation history is append-only and includes every action attempted, its result, and any rollback.

**Acceptance Criteria:**
1. store_remediation_history(incident_id) aggregates:
   - All audit events from the remediation audit table (T10-03)
   - Step Functions execution history
   - Pre and post state snapshots
   - Verification results
2. Written to S3 as evidence/{incident_id}/remediation_history.json
3. Includes executions: array of {execution_id, ction, started_at, completed_at, status, 
esult, 
ollback_performed, 
ollback_result}
4. Written with object-lock retention matching bucket default
5. Reference stored in DynamoDB incidents table under evidence.remediation_history_s3_key

**Tests Required:** Unit tests for: history aggregation from audit events, Step Functions history parsing, write to S3

**Expected Cost Impact:** 🟡[CHARGES] S3 storage negligible

**Manual Verification:** Run test remediation; confirm history JSON written to S3 with correct execution details

---

### Task T14-05: Implement AI Analysis and Verification Results Storage

**Objective:** Build the storage for the AI investigation report, blast radius analysis, and verification results.

**Files/Components Affected:** lambda/evidence/analysis_storage.py, 	ests/unit/test_analysis_storage.py

**AWS Services Involved:** DynamoDB, S3

**Requirements Satisfied:** R14 (AI-analysis storage, verification results)

**Dependencies:** T14-01, T06-04, T08-05, T13-03

**Security Considerations:** AI investigation reports may contain sensitive information about the environment. Stored with KMS encryption and object-lock. AI prompts and raw model responses are NOT stored (only validated reports).

**Acceptance Criteria:**
1. store_investigation_report(incident_id) stores:
   - evidence/{incident_id}/investigation_report.json — validated report from Bedrock
   - evidence/{incident_id}/blast_radius_report.json — blast radius analysis
   - evidence/{incident_id}/verification_results.json — all verification outcomes
2. Raw Bedrock prompts and responses are NOT stored (data minimization)
3. Investigation report includes alidation_status and citation_validation_results
4. Each file written with object-lock retention
5. Manifest updated to include these new files (T14-02)
6. Storage triggered by IncidentResolved or IncidentEscalated event

**Tests Required:** Unit tests for: report storage, blast radius storage, verification results storage, manifest update on new files

**Expected Cost Impact:** 🟡[CHARGES] S3 storage negligible per incident

**Manual Verification:** Complete a test incident lifecycle; confirm all evidence files present in S3; verify manifest includes all files


---

## Phase 15: Incident Reporting

**Goal:** Build the incident report generation engine that produces JSON and Markdown reports with executive summary, timeline, root cause, affected resources, blast radius, actions, evidence, verification, and recommendations.

**Danger Flags in this phase:** 🟡[CHARGES] (Lambda, S3, SNS for report delivery)

### Task T15-01: Implement JSON Report Generator

**Objective:** Build the Lambda that assembles the complete structured incident report in JSON format.

**Files/Components Affected:** lambda/reporting/json_report_generator.py, 	ests/unit/test_json_report_generator.py

**AWS Services Involved:** DynamoDB, S3

**Requirements Satisfied:** R15 (JSON report, all report fields)

**Dependencies:** T14-01 through T14-05 (all evidence stored)

**Security Considerations:** Report includes all investigation data but does not include raw evidence files (only references). Report is stored encrypted in S3.

**Acceptance Criteria:**
1. generate_json_report(incident_id) assembles:
   - incident_id, severity, status, created_at, 
esolved_at/escalated_at, 	ime_to_resolve_seconds
   - executive_summary (from investigation report)
   - 	imeline (from reconstruction, ordered events with attack stages)
   - 
oot_cause (from investigation report summary)
   - ttack_stages_detected (from reconstruction)
   - mitre_attack_techniques (from reconstruction)
   - ffected_principals (from findings)
   - ffected_resources (from findings + blast radius)
   - last_radius (from blast radius report)
   - ctions_taken (from remediation audit log)
   - evidence (manifest reference + file list)
   - erification (verification results)
   - 
ecommendations (from investigation report 
ecommended_actions)
2. Report stored in S3 as evidence/{incident_id}/incident_report.json
3. Report schema validated before storage
4. Triggered by IncidentResolved or IncidentEscalated event

**Tests Required:** Unit tests for: full report assembly with all fields, missing evidence handling, missing blast radius, missing investigation report (escalated case)

**Expected Cost Impact:** 🟡[CHARGES] S3 storage negligible

**Manual Verification:** Complete test incident; confirm JSON report in S3 with all required fields

---

### Task T15-02: Implement Markdown Report Generator

**Objective:** Build the Lambda that renders the incident report as human-readable Markdown.

**Files/Components Affected:** lambda/reporting/markdown_report_generator.py, 	ests/unit/test_markdown_report_generator.py

**AWS Services Involved:** S3

**Requirements Satisfied:** R15 (Markdown report)

**Dependencies:** T15-01

**Security Considerations:** Markdown report includes all information from JSON report in a readable format. Sensitive data (ARNs, IPs) are not redacted in the report — access is controlled at the S3 bucket level.

**Acceptance Criteria:**
1. generate_markdown_report(incident_id) renders:
   - Title: Incident Report: {incident_id}
   - Executive Summary section
   - Timeline section (table with time, event, attack stage, evidence ID)
   - Root Cause Analysis section
   - Attack Stages and MITRE Techniques section
   - Affected Principals table
   - Affected Resources table with sensitivity classification
   - Blast Radius section with risk score
   - Actions Taken table with timestamps
   - Evidence section with manifest reference
   - Verification Results section
   - Recommendations section
2. Report stored in S3 as evidence/{incident_id}/incident_report.md
3. Report includes generated_at timestamp and platform version

**Tests Required:** Unit tests for: full report rendering, missing sections handled gracefully, timeline table formatting

**Expected Cost Impact:** 🟡[CHARGES] S3 storage negligible

**Manual Verification:** Complete test incident; confirm Markdown report in S3 is readable and well-formatted

---

### Task T15-03: Implement Executive Summary Generation

**Objective:** Build the logic that produces a concise executive-level summary for leadership review.

**Files/Components Affected:** lambda/reporting/executive_summary.py, 	ests/unit/test_executive_summary.py

**AWS Services Involved:** None (pure Python logic)

**Requirements Satisfied:** R15 (executive summary)

**Dependencies:** T15-01

**Security Considerations:** Executive summary does not include technical details that could aid attackers (no specific ARNs, no specific IPs). It focuses on impact, actions, and recommendations.

**Acceptance Criteria:**
1. generate_executive_summary(incident_data) produces a 5-10 sentence summary:
   - What happened (1-2 sentences, non-technical)
   - Impact (what was affected, blast radius in business terms)
   - Detection method (which telemetry source)
   - Actions taken (what was done to contain)
   - Current status (resolved/escalated)
   - Key recommendations (1-3 actions)
2. Summary excludes: specific ARNs, IP addresses, access key IDs, credential material
3. Summary is included in both JSON and Markdown reports
4. Summary also published as a separate SNS notification for leadership

**Tests Required:** Unit tests for: summary generation, sensitive data exclusion, length constraints, empty incident handling

**Expected Cost Impact:** 🟡[CHARGES] SNS notification negligible

**Manual Verification:** Run with test incident data; confirm summary is readable, under 10 sentences, contains no ARNs/IPs

---

### Task T15-04: Deploy Report Delivery Pipeline

**Objective:** Wire the reporting pipeline so reports are generated and delivered automatically when incidents are resolved or escalated.

**Files/Components Affected:** 	erraform/modules/eventbridge/reporting-rules.tf, 	erraform/modules/s3/report-delivery-bucket.tf

**AWS Services Involved:** EventBridge, Lambda, S3, SNS

**Requirements Satisfied:** R15 (report delivery)

**Dependencies:** T15-01, T15-02, T15-03

**Security Considerations:** Reports are delivered only to authorized SNS topics and S3 buckets. No public delivery.

**Acceptance Criteria:**
1. EventBridge rule incident-resolved matches detail-type=IncidentResolved and targets reporting Lambda chain
2. EventBridge rule incident-escalated matches detail-type=IncidentEscalated and targets reporting Lambda chain
3. Reporting Lambda chain: JSON report → Markdown report → executive summary → SNS notification
4. Reports stored in evidence bucket under evidence/{incident_id}/reports/
5. SNS topic cloudsec-{env}-reports receives executive summary for stakeholders
6. Lambda timeout: 30 seconds, memory: 512 MB

**Tests Required:** Manual trigger of reporting pipeline; confirm all reports generated and delivered

**Expected Cost Impact:** 🟡[CHARGES] Lambda + SNS negligible

**Manual Verification:** Complete test incident lifecycle; confirm JSON report, Markdown report, and executive summary all generated and delivered to SNS

---

## Phase 16: Knowledge Base

**Goal:** Build the incident knowledge base that stores verified incidents for reference in future investigations — with strict redaction before any data is sent to Bedrock.

**Danger Flags in this phase:** 🟡[CHARGES] (DynamoDB, Bedrock Knowledge Base)

### Task T16-01: Implement Knowledge Base Ingestion (Verified Incidents Only)

**Objective:** Build the Lambda that stores resolved incidents in the knowledge base for future reference.

**Files/Components Affected:** 	erraform/modules/dynamodb/knowledge-base-table.tf, lambda/knowledge_base/kb_ingestor.py, 	ests/unit/test_kb_ingestor.py

**AWS Services Involved:** DynamoDB, EventBridge

**Requirements Satisfied:** R16 (verified incidents only, knowledge base)

**Dependencies:** T15-04 (reports generated for resolved incidents)

**Security Considerations:** Only RESOLVED incidents enter the knowledge base. ESCALATED incidents are excluded (the platform did not successfully handle them). All data is redacted before storage.

**Acceptance Criteria:**
1. Table cloudsec-{env}-knowledge-base with partition key incident_id (String) and sort key ingested_at (String)
2. GSI ttack_stage-index on ttack_stage + ingested_at
3. GSI mitre_technique-index on mitre_technique + ingested_at
4. GSI 
emediation_action-index on 
emediation_action + ingested_at
5. Only incidents with status=RESOLVED are ingested
6. Ingestion triggered by IncidentResolved event
7. Stored fields: incident_id, ttack_stage, mitre_techniques (array), 
emediation_actions (array), 	imeline_pattern (summarized), 
esolution_success (true), last_radius_risk_score, 
oot_cause_category, ingested_at
8. All ARNs, IPs, and credential material are redacted before storage
9. Knowledge base records are NOT sent to Bedrock as raw text — they are used as structured query results

**Tests Required:** Unit tests for: resolved incident ingested, escalated incident rejected, ARN redaction, IP redaction, duplicate incident prevention

**Expected Cost Impact:** 🟡[CHARGES] ~/month at dev scale

**Manual Verification:** Resolve test incident; confirm knowledge base record created with redacted data

---

### Task T16-02: Implement Redaction Engine for Bedrock Queries

**Objective:** Build the redaction layer that sanitizes all data before it is included in Bedrock prompts.

**Files/Components Affected:** lambda/knowledge_base/redactor.py, 	ests/unit/test_redactor.py

**AWS Services Involved:** None

**Requirements Satisfied:** R16 (redaction before Bedrock)

**Dependencies:** T16-01

**Security Considerations:** ⚠️[SECURITY-RISK] This is a critical control — any sensitive data leaked to Bedrock (and potentially to the model provider) is a data breach. Redaction must be exhaustive and fail-closed.

**Acceptance Criteria:**
1. 
edact_for_bedrock(text) removes or masks:
   - IAM ARNs → [REDACTED_ARN]
   - IP addresses (IPv4 and IPv6) → [REDACTED_IP]
   - AWS account IDs → [REDACTED_ACCOUNT]
   - Access key IDs → [REDACTED_KEY]
   - Secret keys, passwords, tokens → [REDACTED_SECRET]
   - Email addresses → [REDACTED_EMAIL]
   - S3 bucket URLs → [REDACTED_S3_URL]
   - DynamoDB table ARNs → [REDACTED_TABLE]
2. Redaction uses regex patterns defined in lambda/knowledge_base/redaction_patterns.py
3. 
edact_incident_data(incident_data) applies redaction to all string fields in the incident JSON
4. 
edact_finding_data(finding) applies redaction to finding fields
5. 
edact_evidence(evidence) applies redaction to evidence text
6. If redaction fails (exception), the data is NOT sent to Bedrock — investigation is escalated
7. All redaction patterns are tested against known sensitive data patterns

**Tests Required:** Unit tests for: each redaction pattern matches correctly, no false positives (normal text not redacted), failed redaction blocks Bedrock call, nested JSON redaction

**Expected Cost Impact:** 

**Manual Verification:** Run redactor against test data with ARNs, IPs, keys; confirm all are redacted; confirm no normal text is affected

---

### Task T16-03: Implement Knowledge Base Query Patterns for Investigation

**Objective:** Build the query patterns that retrieve relevant knowledge base entries to include in Bedrock prompts during investigation.

**Files/Components Affected:** lambda/knowledge_base/kb_query.py, 	ests/unit/test_kb_query.py

**AWS Services Involved:** DynamoDB

**Requirements Satisfied:** R16 (knowledge query patterns)

**Dependencies:** T16-01, T16-02

**Security Considerations:** Query results are redacted before being sent to Bedrock. Maximum 5 knowledge base entries are included per investigation to limit prompt size.

**Acceptance Criteria:**
1. query_knowledge_base(incident_data) retrieves relevant entries using:
   - ttack_stage match (GSI query)
   - mitre_technique match (GSI query)
   - 
oot_cause_category match (filter)
2. Results sorted by relevance score: same attack_stage (+3), same MITRE technique (+2), same root cause (+1)
3. Maximum 5 entries returned
4. Entries redacted via T16-02 before inclusion in Bedrock prompt
5. Knowledge base entries formatted as "Previous Incident: {summary}" in the prompt
6. If knowledge base is empty (no prior incidents), prompt does not include knowledge section
7. Query runs in <500ms (DynamoDB GSI query, no scan)

**Tests Required:** Unit tests (moto) for: relevant entries returned, max 5 entries, empty knowledge base, redaction applied to results, query performance

**Expected Cost Impact:** 

**Manual Verification:** Seed knowledge base with test entries; query for a matching incident; confirm relevant entries returned and redacted


---

## Phase 17: Observability

**Goal:** Build the complete observability layer — CloudWatch dashboards, alarms, structured logs, and metrics for every component.

**Danger Flags in this phase:** 🟡[CHARGES] (CloudWatch dashboards, custom metrics, alarms)

### Task T17-01: Implement Structured Logging Across All Components

**Objective:** Establish consistent structured logging (JSON format) across all Lambda functions.

**Files/Components Affected:** lambda/common/logger.py, all Lambda functions (import and configure)

**AWS Services Involved:** CloudWatch Logs

**Requirements Satisfied:** R17 (structured logs)

**Dependencies:** None (can be implemented at any phase)

**Security Considerations:** Logs must not contain secrets, credentials, or full Bedrock prompts. Structured logs enable efficient querying via CloudWatch Logs Insights.

**Acceptance Criteria:**
1. lambda/common/logger.py provides get_logger(name) returning a structured JSON logger
2. Every log entry includes: 	imestamp (ISO 8601 UTC), level, unction_name, 
equest_id, incident_id (if applicable), message
3. Error logs include error_type, error_message, stack_trace
4. Log groups follow naming: cloudsec/{env}/{component}
5. Log retention: 30 days (dev), 365 days (prod)
6. All existing Lambda functions import and use the structured logger

**Tests Required:** Unit test for logger output format; confirm JSON structure is valid

**Expected Cost Impact:** 🟡[CHARGES] CloudWatch Logs ~.50/GB ingested

**Manual Verification:** Invoke a Lambda; confirm CloudWatch Logs shows structured JSON entries

---

### Task T17-02: Implement Lambda Failure Metrics and Alarms

**Objective:** Create CloudWatch metrics and alarms for Lambda function failures.

**Files/Components Affected:** 	erraform/modules/cloudwatch/lambda-metrics.tf, 	erraform/modules/cloudwatch/lambda-alarms.tf

**AWS Services Involved:** CloudWatch, SNS

**Requirements Satisfied:** R17 (Lambda failure metrics)

**Dependencies:** T17-01

**Security Considerations:** Alarms notify the Security Account SNS topic for visibility across accounts.

**Acceptance Criteria:**
1. CloudWatch alarm per Lambda function:
   - Errors > 0 over 5 minutes → P2 alert
   - Throttles > 0 over 5 minutes → P2 alert
   - Duration > 90% of timeout over 5 minutes → P3 alert
2. Alarms send to cloudsec-{env}-errors SNS topic
3. Composite alarm cloudsec-{env}-lambda-health aggregates all Lambda alarms
4. Metric widget per Lambda showing: Invocations, Errors, Duration, Throttles

**Tests Required:** Manual test: force a Lambda error; confirm alarm fires within 5 minutes

**Expected Cost Impact:** 🟡[CHARGES] CloudWatch alarms ~.10/alarm/month

**Manual Verification:** Deploy alarms; trigger test error; confirm alarm transitions to ALARM state

---

### Task T17-03: Implement Step Functions Failure Metrics and Alarms

**Objective:** Create CloudWatch metrics and alarms for Step Functions execution failures.

**Files/Components Affected:** 	erraform/modules/cloudwatch/sf-metrics.tf

**AWS Services Involved:** CloudWatch, Step Functions

**Requirements Satisfied:** R17 (Step Functions failure metrics)

**Dependencies:** T10-01

**Security Considerations:** Step Functions failure metrics help detect remediation execution problems quickly.

**Acceptance Criteria:**
1. CloudWatch alarm: Step Functions Failures > 0 over 10 minutes → P2 alert
2. CloudWatch alarm: Step Functions TimedOut > 0 over 10 minutes → P2 alert
3. Alarms send to cloudsec-{env}-errors SNS topic
4. Step Functions execution duration metric dashboarded

**Tests Required:** Manual test: trigger Step Functions failure; confirm alarm fires

**Expected Cost Impact:** 🟡[CHARGES] Alarms negligible

**Manual Verification:** Deploy alarms; trigger test Step Functions failure; confirm alarm

---

### Task T17-04: Implement Bedrock Failure and Invalid Response Metrics

**Objective:** Create CloudWatch metrics for Bedrock invocation outcomes and schema validation failures.

**Files/Components Affected:** 	erraform/modules/cloudwatch/bedrock-metrics.tf, lambda/common/bedrock_metrics.py

**AWS Services Involved:** CloudWatch, Bedrock

**Requirements Satisfied:** R17 (Bedrock failures, invalid AI responses)

**Dependencies:** T06-04, T06-05

**Security Considerations:** Invalid AI response metrics are a leading indicator of prompt engineering problems or model behavior changes.

**Acceptance Criteria:**
1. Custom metrics emitted by investigation Lambda:
   - BedrockInvocation (count)
   - BedrockSuccess (count)
   - BedrockFailure (count) with dimension ailure_reason
   - SchemaValidationError (count) with dimension alidation_stage
   - CitationValidationError (count)
   - HallucinationDetected (count)
2. CloudWatch alarm: SchemaValidationError > 3 in 1 hour → P2 alert
3. CloudWatch alarm: BedrockFailure > 5 in 1 hour → P2 alert
4. CloudWatch alarm: HallucinationDetected > 0 in 1 hour → P3 alert (investigate model behavior)
5. Metrics dashboarded in Bedrock section of main dashboard

**Tests Required:** Unit test for metric emission; manual trigger of schema validation failure; confirm metric appears

**Expected Cost Impact:** 🟡[CHARGES] CloudWatch custom metrics ~.30/metric/month

**Manual Verification:** Deploy; trigger test investigation; confirm metrics in CloudWatch

---

### Task T17-05: Implement Failed Remediation and Verification Failure Metrics

**Objective:** Create CloudWatch metrics for remediation and verification outcomes.

**Files/Components Affected:** 	erraform/modules/cloudwatch/remediation-metrics.tf

**AWS Services Involved:** CloudWatch, DynamoDB

**Requirements Satisfied:** R17 (failed remediation, verification failures)

**Dependencies:** T10-03, T13-03

**Security Considerations:** Failed remediation and verification failures are critical operational signals.

**Acceptance Criteria:**
1. Custom metrics emitted:
   - RemediationExecuted (count) with dimension ction
   - RemediationFailed (count) with dimension ction
   - VerificationPassed (count)
   - VerificationFailed (count) with dimension ailure_type
   - IncidentResolved (count)
   - IncidentEscalated (count) with dimension escalation_reason
2. CloudWatch alarm: VerificationFailed > 0 over 15 minutes → P2 alert
3. CloudWatch alarm: IncidentEscalated > 0 over 15 minutes → P1 alert (requires immediate attention)
4. Metrics dashboarded in Remediation section of main dashboard

**Tests Required:** Manual test: trigger failed verification; confirm metric and alarm

**Expected Cost Impact:** 🟡[CHARGES] CloudWatch custom metrics ~.30/metric/month

**Manual Verification:** Deploy; trigger test verification failure; confirm metric appears in CloudWatch

---

### Task T17-06: Deploy CloudWatch Dashboards

**Objective:** Create comprehensive CloudWatch dashboards for the entire platform.

**Files/Components Affected:** 	erraform/modules/cloudwatch/dashboards.tf

**AWS Services Involved:** CloudWatch

**Requirements Satisfied:** R17 (CloudWatch dashboards)

**Dependencies:** T17-01 through T17-05

**Security Considerations:** Dashboards are internal — no public access. Dashboard names follow naming standard.

**Acceptance Criteria:**
1. Dashboard cloudsec-{env}-overview with sections:
   - Telemetry Ingestion: findings per source per hour, DLQ depth, ingestion lag
   - Incidents: open incidents by severity, incidents per day, time-to-resolve
   - AI Investigation: Bedrock invocations, success rate, schema validation failures
   - Remediation: executions per action, success/failure rate, verification pass/fail
   - System Health: Lambda errors/throttles, Step Functions failures, DynamoDB throughput
2. Dashboard cloudsec-{env}-cost with sections:
   - Total spend per service per day
   - Bedrock spend per day
   - Cost vs budget (from T01-08)
3. Dashboard cloudsec-{env}-security with sections:
   - Active alarms
   - Escalated incidents
   - High-severity findings per hour
   - Anomaly detection scores
4. All dashboards use the same time range (last 24 hours default)
5. Dashboard URLs documented in docs/observability.md

**Tests Required:** Manual: deploy dashboards; confirm widgets render correctly

**Expected Cost Impact:** 🟡[CHARGES] Dashboards are free; underlying metrics have cost as noted above

**Manual Verification:** Open each dashboard in CloudWatch console; confirm all widgets render with data


---

## Phase 18: Safe Attack Simulations

**Goal:** Create isolated lab scenarios that demonstrate all six supported incident types. No destructive activity outside resources created specifically for this project.

**Danger Flags in this phase:** 🟡[CHARGES] (lab resources, EC2 instances, IAM users), 🔴[HARD-TO-DELETE] (lab IAM users, S3 buckets), ⚠️[SECURITY-RISK] (simulations could be confused with real attacks if not properly isolated)

### Task T18-01: Provision Isolated Lab Environment

**Status:** COMPLETE (shared-account strict-isolation variant deployed and verified 2026-09-04; separate state, isolated VPC, no peering/transit attachments, dedicated CloudTrail, GuardDuty, Security Hub, and bounded lab operator)

**Objective:** Create the dedicated lab environment with no trust relationship to production resources.

**Files/Components Affected:** 	erraform/environments/lab/ (separate environment with lab backend)

**AWS Services Involved:** IAM, EC2, S3, CloudTrail, GuardDuty, Security Hub

**Requirements Satisfied:** R18 (isolated lab, no destructive activity outside project resources)

**Dependencies:** T01-01 through T01-08 (foundation must be deployed in lab account too)

**Security Considerations:** ⚠️[SECURITY-RISK] Lab environment MUST have:
- No IAM trust relationships to production accounts
- No VPC peering or Transit Gateway connections to production
- No S3 bucket policies allowing production access
- Separate CloudTrail trail (not the org trail)
- All resources tagged Environment=lab, Isolation=strict
- A single IAM user cloudsec-lab-admin with Admin access (only in lab)

**Acceptance Criteria:**
1. Lab deployed in a separate AWS account (or same account with strict resource isolation)
2. All foundation components (T01) deployed in lab with env=lab
3. All platform components deployed in lab with env=lab
4. GuardDuty enabled in lab account
5. Security Hub enabled in lab account
6. CloudTrail deployed in lab (separate from org trail)
7. Lab resources have no cross-account access to production
8. Lab cleanup script scripts/cleanup-lab.sh deletes all lab resources

**Tests Required:** Verify no IAM trust policies reference production accounts; verify no VPC connections to production

**Expected Cost Impact:** 🟡[CHARGES] Lab cost same as dev deployment (~-30/month); lab is shut down when not in use

**Manual Verification:** ws iam list-role-policies in lab; confirm no production ARNs; verify no VPC peering connections

---

### Task T18-02: Build Simulation Scenarios for All Six Incident Types

**Status:** COMPLETE (all six guarded simulations executed 2026-09-04; temporary resources cleaned up and lab trail restored)

**Objective:** Create the simulation scripts and test resources for each incident type.

**Files/Components Affected:** lab/simulations/simulate_compromised_iam_key.py, lab/simulations/simulate_sg_change.py, lab/simulations/simulate_public_s3.py, lab/simulations/simulate_ec2_compromise.py, lab/simulations/simulate_cloudtrail_tamper.py, lab/simulations/simulate_privilege_escalation.py

**AWS Services Involved:** IAM, EC2, S3, CloudTrail, Security Hub

**Requirements Satisfied:** R18 (six incident types, safe simulations)

**Dependencies:** T18-01

**Security Considerations:** ⚠️[SECURITY-RISK] Every simulation script:
- Creates its own test resources (IAM users, S3 buckets, EC2 instances) in the lab only
- Never operates on resources outside the lab
- Logs all actions to CloudWatch for audit
- Includes a cleanup function that removes all created resources
- Prints a banner: SIMULATION — NOT A REAL ATTACK

**Acceptance Criteria:**
1. simulate_compromised_iam_key(): creates IAM user with access key, makes suspicious API calls (CreateBucket in unusual region, PutObject with sensitive filename)
2. simulate_sg_change(): creates EC2 instance with SG, adds 0.0.0.0/0 ingress rule on SSH port
3. simulate_public_s3(): creates S3 bucket, sets public ACL, uploads test object
4. simulate_ec2_compromise(): launches EC2 instance, creates key pair, simulates unauthorized SSH
5. simulate_cloudtrail_tamper(): creates a separate CloudTrail, stops logging
6. simulate_privilege_escalation(): creates IAM role, attaches Admin policy, simulates privilege escalation
7. Each script has a --cleanup flag that removes all created resources
8. Each script outputs the finding IDs or event IDs generated for verification
9. No script runs without --lab flag confirming lab environment

**Tests Required:** Run each simulation; confirm expected findings are generated; confirm cleanup removes resources

**Expected Cost Impact:** 🟡[CHARGES] ~-15 per simulation run (EC2 instances, S3 storage); lab is short-lived

**Manual Verification:** Run each simulation; confirm findings appear in GuardDuty/Security Hub/CloudTrail; confirm cleanup works

---

### Task T18-03: Create Simulation Orchestration Script

**Status:** COMPLETE (dry-run, confirmed execution, retrying Security Hub validation, and cleanup paths verified 2026-09-04; six unique practice finding IDs validated)

**Objective:** Build a single script that runs all six simulations sequentially with proper wait times and cleanup.

**Files/Components Affected:** lab/simulations/run_all_simulations.sh, lab/simulations/validate_simulations.py

**AWS Services Involved:** CloudWatch, GuardDuty, Security Hub

**Requirements Satisfied:** R18 (end-to-end simulation orchestration)

**Dependencies:** T18-02

**Security Considerations:** Orchestration script has --dry-run mode that prints what would be executed without running anything. --confirm flag required for actual execution.

**Acceptance Criteria:**
1. 
un_all_simulations.sh runs all six simulations sequentially
2. Between each simulation: 2-minute wait for findings to propagate
3. After all simulations: alidate_simulations.py checks that findings were created for each incident type
4. Output: simulation log with pass/fail for each incident type
5. --cleanup flag runs cleanup for all simulations
6. --dry-run mode prints actions without executing
7. Script exits non-zero if any simulation fails to generate findings
8. Total run time: <15 minutes

**Tests Required:** --dry-run mode works; --cleanup mode removes resources; full run generates all 6 finding types

**Expected Cost Impact:** 🟡[CHARGES] Full simulation run ~-20

**Manual Verification:** Run with --dry-run; run full simulation; confirm all 6 findings in DynamoDB; run --cleanup; confirm resources removed

---

### Task T18-04: Document Lab Operations and Safety Procedures

**Status:** COMPLETE (`docs/lab-operations.md` documents architecture, deployment, execution, validation, cleanup, emergency response, cost, and troubleshooting)

**Objective:** Write the lab operations guide covering setup, simulation execution, safety procedures, and cleanup.

**Files/Components Affected:** docs/lab-operations.md

**AWS Services Involved:** None

**Requirements Satisfied:** R18 (documentation)

**Dependencies:** T18-01, T18-02, T18-03

**Security Considerations:** Documentation includes safety warnings, emergency cleanup procedures, and what to do if a simulation affects production (should be impossible but documented).

**Acceptance Criteria:**
1. docs/lab-operations.md includes:
   - Lab environment architecture diagram
   - How to deploy the lab (	erraform apply -environment=lab)
   - How to run individual simulations
   - How to run all simulations
   - How to verify findings were generated
   - How to clean up the lab
   - Emergency cleanup procedure (delete everything in <5 minutes)
   - Safety warnings (never run simulations in production)
   - Cost estimate for lab usage
   - Troubleshooting common simulation failures

**Tests Required:** None (documentation)

**Expected Cost Impact:** 

**Manual Verification:** Read lab-operations.md; confirm all steps are documented and clear


---

## Phase 19: End-to-End Testing

**Goal:** Validate the complete CloudSec AI lifecycle end-to-end, from attack simulation through incident resolution, covering all success paths, failure modes, edge cases, and safety guarantees.

**Danger Flags in this phase:** 🟡[CHARGES] (lab resources for test execution), ⚠️[SECURITY-RISK] (tests exercise all platform components including automated remediation)

**Manual Checkpoint:** End of Phase 19 — confirm every test scenario passes and all safety guarantees are upheld before proceeding to portfolio and demo.

### Task T19-01: Implement End-to-End Test Framework and Harness

**Status:** COMPLETE (lab guardrails, encrypted SSM configuration, 12-scenario registry, and read-only harness validation passed 2026-09-05)

**Objective:** Build the E2E test harness that orchestrates the full incident lifecycle test scenarios.

**Files/Components Affected:** 	ests/e2e/__init__.py, 	ests/e2e/test_harness.py, 	ests/e2e/conftest.py, 	ests/e2e/test_config.py

**AWS Services Involved:** Lambda, Step Functions, DynamoDB, EventBridge, SNS, S3

**Requirements Satisfied:** R2, R17 (testing foundation for all requirements)

**Dependencies:** T18-01 (lab environment), T18-02 (simulation scripts), T17-06 (observability dashboards)

**Security Considerations:** E2E tests run only in the lab environment. Test harness verifies AWS_REGION and account ID match the lab environment before executing any tests. No test runs against dev or prod.

**Acceptance Criteria:**
1. 	ests/e2e/test_harness.py provides:
   - E2ETestRunner class with 
un_test(scenario_name), cleanup(), ssert_incident_resolved(incident_id), ssert_incident_escalated(incident_id)
   - Test configuration loaded from SSM Parameter Store (/cloudsec/lab/e2e/)
   - Lab environment validation at test start (account ID check)
2. 	ests/e2e/conftest.py provides pytest fixtures:
   - lab_account_id — validated lab account
   - e2e_runner — initialized test runner
   - clean_findings — clears findings table before each test
   - wait_for_event — polling helper for EventBridge events
3. 	ests/e2e/test_config.py defines scenario configurations:
   - SCENARIO_CONFIGS dict mapping scenario names to expected outcomes
4. Test timeout: 10 minutes per scenario
5. Tests are parameterized to run against all six incident types where applicable

**Tests Required:** pytest tests/e2e/test_harness.py -v --run-e2e (requires --run-e2e flag to prevent accidental execution); harness self-test validates lab environment

**Expected Cost Impact:** 🟡[CHARGES] ~-30 per full E2E test run

**Manual Verification:** Run pytest tests/e2e/test_harness.py -v --run-e2e --dry-run; confirm lab validation passes and all scenario configs are loaded

---

### Task T19-02: Test Scenario — Successful Automatic Remediation (Level 1)

**Status:** IMPLEMENTED — LIVE LAB CHECKPOINT PENDING

**Objective:** Verify the complete lifecycle for a Level 1 automated remediation (Public S3 Exposure → automatic block).

**Files/Components Affected:** 	ests/e2e/scenarios/test_level1_auto_remediation.py

**AWS Services Involved:** S3, EventBridge, DynamoDB, Bedrock, Step Functions, Lambda, SNS

**Requirements Satisfied:** R1, R2, R4, R6, R7, R8, R9, R10, R11, R13, R14, R15

**Dependencies:** T19-01, T11-03 (S3 playbook), T09-05 (safety engine), T13-03 (verification)

**Security Considerations:** This test exercises the full automatic path — no human approval needed. Verify that the safety engine correctly classifies this as Level 1 and that remediation executes without human intervention.

**Acceptance Criteria:**
1. Test flow: simulate_public_s3 → telemetry ingestion → finding in DynamoDB → correlation → incident creation → Bedrock investigation → evidence validation → attack reconstruction → blast radius → safety validation → Level 1 decision → Step Functions → S3 public access block → verification → RESOLVED
2. Assertions:
   - Finding appears in DynamoDB within 5 minutes of simulation
   - Incident created within 10 seconds of correlation
   - Investigation report has alidation_status=APPROVED
   - Safety decision is level=1
   - Step Functions execution completes successfully
   - S3 bucket public access block is enabled (post-verification)
   - Incident status is RESOLVED within 15 minutes of simulation
   - Evidence bucket contains all expected files (config snapshot, remediation history, investigation report, manifest)
   - Incident report JSON and Markdown generated
3. Test maps back to: R1 (telemetry), R2 (lifecycle), R4 (correlation), R6 (AI investigation), R7 (reconstruction), R8 (blast radius), R9 (safety validation), R10 (remediation framework), R11 (S3 playbook), R13 (verification), R14 (evidence), R15 (reporting)

**Tests Required:** Full E2E scenario; each assertion is a separate test method within the scenario class

**Expected Cost Impact:** 🟡[CHARGES] ~-5 per run (S3 bucket, Bedrock call, Lambda invocations)

**Manual Verification:** Run scenario manually; confirm each stage completes; check CloudWatch Logs for each Lambda invocation; verify S3 bucket access block; confirm incident report

---

### Task T19-03: Test Scenario — Approval-Required Remediation (Level 2)

**Status:** IMPLEMENTED — LIVE LAB CHECKPOINT PENDING

**Objective:** Verify the complete lifecycle for a Level 2 remediation requiring human approval (Compromised IAM Credential → key disable).

**Files/Components Affected:** 	ests/e2e/scenarios/test_level2_approval_remediation.py

**AWS Services Involved:** IAM, EventBridge, DynamoDB, Bedrock, Step Functions, API Gateway, Cognito, Lambda

**Requirements Satisfied:** R2, R6, R9, R10, R11, R12, R13, R14, R15

**Dependencies:** T19-01, T11-01 (IAM key playbook), T12-01 (approval API)

**Security Considerations:** This test requires a Cognito test user in the cloudsec_approver group. Test verifies that remediation does NOT execute until approval is granted.

**Acceptance Criteria:**
1. Test flow: simulate_compromised_iam_key → telemetry → finding → correlation → incident → Bedrock investigation → safety validation → Level 2 decision → Step Functions WaitForApproval → (wait) → API approve → Step Functions resumes → IAM key disabled → verification → RESOLVED
2. Assertions:
   - Safety decision is level=2
   - Step Functions enters WaitForApproval state
   - IAM key is NOT disabled while waiting for approval (assert key still Active after 5 minutes)
   - Pending approval decision is visible via GET /decisions/pending
   - Approval via API with valid Cognito token succeeds
   - Step Functions resumes after approval and completes remediation
   - IAM key is Inactive after remediation
   - Incident status is RESOLVED
3. Sub-test: rejection path — reject the decision via API; confirm Step Functions completes with failure; incident transitions to ESCALATED

**Tests Required:** Full E2E scenario with approval path; sub-test with rejection path; assertion that key remains Active during wait period

**Expected Cost Impact:** 🟡[CHARGES] ~-5 per run (Bedrock, IAM, API Gateway calls)

**Manual Verification:** Run scenario; monitor Step Functions execution reaching WaitForApproval; approve via API; confirm remediation completes

---

### Task T19-04: Test Scenario — Rejected Unsafe AI Action (Level 3)

**Status:** IMPLEMENTED — LIVE LAB CHECKPOINT PENDING

**Objective:** Verify that a malformed or unsupported AI remediation recommendation is correctly rejected as Level 3 and does not execute.

**Files/Components Affected:** 	ests/e2e/scenarios/test_level3_rejected_action.py

**AWS Services Involved:** DynamoDB, Bedrock (mocked), Lambda

**Requirements Satisfied:** R6, R9 (schema validation, evidence validation, policy validation, Level 3 precedence)

**Dependencies:** T19-01, T09-02, T09-03, T09-04

**Security Considerations:** ⚠️[SECURITY-RISK] This test verifies the critical safety guarantee: no unrecognized action is ever executed. Test injects a known-invalid recommendation and confirms the safety engine blocks it at each stage.

**Acceptance Criteria:**
1. Test scenarios:
   - Unknown action name (e.g., delete_all_buckets) → schema validation fails → Level 3
   - Valid action but params not in evidence (e.g., bucket not in investigation report) → evidence validation fails → Level 3
   - Valid action but pplicable_when condition false → policy validation fails → Level 3
2. Assertions for each:
   - Safety decision is level=3
   - No Step Functions execution is triggered
   - No AWS state-changing API calls are made
   - RemediationRejected event is published
   - Incident is NOT transitioned to REMEDIATING
   - Incident is escalated with escalation_reason=safety_validation_failed
   - Audit log records the rejection with reason

**Tests Required:** 3 sub-tests (one per rejection reason); each with all assertions above

**Expected Cost Impact:** 🟡[CHARGES] Negligible (no Bedrock call in mocked test)

**Manual Verification:** Run each sub-test; confirm no Step Functions execution; confirm audit log records rejection

---

### Task T19-05: Test Scenario — Malformed Bedrock Response

**Status:** IMPLEMENTED — LIVE LAB CHECKPOINT PENDING

**Objective:** Verify that a malformed or non-JSON Bedrock response is handled correctly with retry and eventual failure escalation.

**Files/Components Affected:** 	ests/e2e/scenarios/test_malformed_bedrock_response.py

**AWS Services Involved:** Bedrock (mocked), Lambda, DynamoDB, SNS

**Requirements Satisfied:** R6 (schema validation, retry behavior, failure handling)

**Dependencies:** T19-01, T06-04, T06-05

**Security Considerations:** Malformed responses must never be executed. This test uses a mocked Bedrock client to return controlled malformed responses.

**Acceptance Criteria:**
1. Test scenarios:
   - Bedrock returns non-JSON string → parse failure → retry
   - Bedrock returns JSON but missing required fields → schema validation fails → retry
   - Bedrock returns JSON with invalid enum values → schema validation fails → retry
   - All retries exhausted → InvestigationFailed event → incident escalated
2. Assertions:
   - Retry count matches configured 
etry_max (3)
   - Each retry is logged with 
etry_reason
   - BedrockFinalFailure CloudWatch metric is emitted
   - Investigation report has alidation_status=REJECTED (if partially valid) or no report (if completely malformed)
   - Incident transitions to ESCALATED with escalation_reason=investigation_failed
   - No remediation is attempted

**Tests Required:** 4 sub-tests (one per malformed response type); retry count assertion; metric assertion; escalation assertion

**Expected Cost Impact:** 🟡[CHARGES] Negligible (mocked Bedrock)

**Manual Verification:** Run scenario; confirm retries in CloudWatch Logs; confirm escalation; verify no remediation Lambda was invoked

---

### Task T19-06: Test Scenario — Bedrock Timeout and Service Failure

**Status:** IMPLEMENTED — LIVE LAB CHECKPOINT PENDING

**Objective:** Verify that Bedrock timeouts and service unavailability are handled with correct retry behavior and graceful degradation.

**Files/Components Affected:** 	ests/e2e/scenarios/test_bedrock_timeout_failure.py

**AWS Services Involved:** Bedrock (mocked), Lambda, DynamoDB, SNS

**Requirements Satisfied:** R6 (retry/timeout behavior), R2 (DynamoDB retry on failure)

**Dependencies:** T19-01, T06-06 (retry handler)

**Security Considerations:** Service failures must not cause data loss or orphaned incidents. Incident state is preserved even if investigation fails.

**Acceptance Criteria:**
1. Test scenarios:
   - Bedrock ThrottlingException → retry with backoff (1s, 2s, 4s) → eventual success or failure
   - Bedrock ServiceUnavailableException → retry with backoff → eventual success or failure
   - Bedrock socket timeout (45s) → treated as transient failure → retry
   - DynamoDB ProvisionedThroughputExceededException on incident update → retry → eventual success
2. Assertions:
   - Backoff intervals match expected values (1s, 2s, 4s)
   - BedrockRetryCount metric incremented with correct 
etry_reason dimension
   - On final success after retries: investigation completes normally
   - On final failure: incident escalated, no remediation attempted
   - Incident record is not lost (exists in DynamoDB with status=INVESTIGATING during retry)

**Tests Required:** 4 sub-tests (one per failure type); backoff timing assertion; metric assertion; state preservation assertion

**Expected Cost Impact:** 🟡[CHARGES] Negligible (mocked Bedrock)

**Manual Verification:** Run scenario; confirm retry intervals in logs; confirm metric emissions; verify incident state preserved

---

### Task T19-07: Test Scenario — Failed Remediation and Rollback

**Status:** IMPLEMENTED — LIVE LAB CHECKPOINT PENDING

**Objective:** Verify that a failed remediation triggers rollback (where applicable), escalates the incident, and preserves audit trail.

**Files/Components Affected:** 	ests/e2e/scenarios/test_failed_remediation_rollback.py

**AWS Services Involved:** IAM (mocked), Step Functions, DynamoDB, S3, Lambda

**Requirements Satisfied:** R10 (failure handling, rollback), R13 (escalation on verification failure), R14 (evidence preservation)

**Dependencies:** T19-01, T10-04 (rollback), T13-03 (resolution engine)

**Security Considerations:** ⚠️[SECURITY-RISK] Failed remediation must never leave the system in an inconsistent state. Rollback must be verified, not just attempted.

**Acceptance Criteria:**
1. Test scenarios:
   - IAM DisableKey fails with AccessDeniedException → rollback re-enables key (if it was changed) → incident escalated
   - S3 PutPublicAccessBlock fails with AccessDenied → rollback re-applies previous config → incident escalated
   - Step Functions Lambda timeout during playbook execution → Step Functions Catch → OnFailure → incident escalated
2. Assertions:
   - Rollback is attempted for actions with rollback handlers
   - Rollback success/failure is logged to audit table
   - Incident transitions to ESCALATED with escalation_reason=remediation_failed
   - Pre-remediation state is restored (verified by re-querying AWS)
   - SNS escalation notification is sent within 30 seconds
   - Evidence bucket contains pre-remediation config snapshot
   - RemediationFailed event is published

**Tests Required:** 3 sub-tests (one per failure type); rollback verification assertion; audit trail assertion; escalation notification assertion

**Expected Cost Impact:** 🟡[CHARGES] Negligible (mocked AWS failures)

**Manual Verification:** Run scenario; confirm rollback in audit log; verify resource state restored; confirm escalation notification in SNS

---

### Task T19-08: Test Scenario — Failed Verification and Escalation

**Status:** IMPLEMENTED — LIVE LAB CHECKPOINT PENDING

**Objective:** Verify that failed post-remediation verification correctly escalates the incident and does not falsely resolve it.

**Files/Components Affected:** 	ests/e2e/scenarios/test_failed_verification.py

**AWS Services Involved:** DynamoDB, S3, SNS, Lambda

**Requirements Satisfied:** R13 (re-check findings, confirm containment, RESOLVE or ESCALATE)

**Dependencies:** T19-01, T13-01, T13-02, T13-03

**Security Considerations:** ⚠️[SECURITY-RISK] False resolution is a critical failure. This test deliberately creates a scenario where remediation appears to succeed but verification fails, confirming the engine does not resolve the incident.

**Acceptance Criteria:**
1. Test scenarios:
   - Remediation succeeds (key disabled) but finding is still ACTIVE in GuardDuty → verification fails → escalated
   - Remediation succeeds but new findings appear for same incident within 5 minutes → verification fails → escalated
   - State check passes but containment check fails (finding still active) → escalated
2. Assertions:
   - Incident status is ESCALATED, NOT RESOLVED
   - erification_failures field in incident record lists the specific failures
   - SNS escalation notification includes containment_confirmed=false
   - IncidentEscalated event published with escalation_reason=verification_failed
   - Evidence preservation still occurs (evidence bucket populated)
   - Incident report is generated (for escalated incidents too)

**Tests Required:** 3 sub-tests; each with RESOLVED-never-asserted assertion (critical safety check)

**Expected Cost Impact:** 🟡[CHARGES] Negligible

**Manual Verification:** Run scenario; confirm incident is ESCALATED not RESOLVED; verify escalation notification content

---

### Task T19-09: Test Scenario — Duplicate Events and Idempotency

**Status:** IMPLEMENTED — LIVE LAB CHECKPOINT PENDING

**Objective:** Verify that duplicate findings and duplicate remediation executions are handled correctly without causing double-processing or double-execution.

**Files/Components Affected:** 	ests/e2e/scenarios/test_duplicate_events_idempotency.py

**AWS Services Involved:** DynamoDB, Lambda, EventBridge

**Requirements Satisfied:** R1 (parse failure handling), R2 (incident creation within 10 seconds, idempotency), R10 (idempotency)

**Dependencies:** T19-01, T02-06 (incident state machine), T10-02 (idempotency)

**Security Considerations:** Duplicate events must not create duplicate incidents or duplicate remediation executions.

**Acceptance Criteria:**
1. Test scenarios:
   - Same finding ingested twice → second ingestion deduplicated (not written to DynamoDB) → single incident created
   - Same incident_id attempted for creation twice → second attempt uses existing record (idempotent)
   - Remediation Step Functions triggered twice for same incident → second execution blocked by idempotency lock
   - Correlation engine receives duplicate finding set → produces single incident (not two)
2. Assertions:
   - Findings table has exactly 1 record for duplicated finding (not 2)
   - Incidents table has exactly 1 record (not 2)
   - Step Functions has exactly 1 successful execution (second is blocked or returns existing result)
   - Idempotency table shows lock was held and released
   - No duplicate IncidentCreated events on EventBridge
   - No duplicate RemediationExecuted events on EventBridge

**Tests Required:** 4 sub-tests; count assertions for each table and event type

**Expected Cost Impact:** 🟡[CHARGES] Negligible

**Manual Verification:** Run scenario; query DynamoDB for record count; confirm exactly 1 incident and 1 finding

---

### Task T19-10: Test Scenario — Cross-Account Events

**Status:** IMPLEMENTED — LIVE LAB CHECKPOINT PENDING

**Objective:** Verify that cross-account telemetry events are correctly ingested, correlated, and handled in the multi-account architecture.

**Files/Components Affected:** 	ests/e2e/scenarios/test_cross_account_events.py

**AWS Services Involved:** EventBridge, DynamoDB, CloudTrail, GuardDuty

**Requirements Satisfied:** R1 (cross-account ingestion), R4 (cross-account correlation), R7 (cross-account labeling)

**Dependencies:** T19-01, T03-01 through T03-05, T07-04

**Security Considerations:** Cross-account events must not leak findings across account boundaries unless explicitly configured. Test verifies the cross-account correlation flag behavior.

**Acceptance Criteria:**
1. Test scenarios:
   - GuardDuty finding from Workload Account delivered to Security Account via cross-account EventBridge → ingested correctly with source_account tagged
   - CloudTrail event from Workload Account in Security Account S3 bucket → parsed and ingested with correct source_account
   - Correlation across accounts: same principal in two accounts → correlated only if cross_account_correlation=true in config
   - Cross-account AssumeRole event → labeled lateral_movement=true in reconstruction
2. Assertions:
   - Findings from Workload Account have correct source_account field
   - Cross-account correlation is disabled by default (config flag)
   - Cross-account events are tagged correctly in reconstruction
   - Blast radius includes cross-account roles when applicable
   - Incident report includes cross_account_summary

**Tests Required:** 4 sub-tests; source_account tagging assertion; cross-account correlation flag behavior

**Expected Cost Impact:** 🟡[CHARGES] Negligible

**Manual Verification:** Run scenario; confirm findings have correct source_account; verify cross-account correlation behavior

---

### Task T19-11: Test Scenario — Insufficient Evidence

**Status:** IMPLEMENTED — LIVE LAB CHECKPOINT PENDING

**Objective:** Verify that the platform handles incidents where the AI investigation report has insufficient or no supporting evidence correctly.

**Files/Components Affected:** 	ests/e2e/scenarios/test_insufficient_evidence.py

**AWS Services Involved:** DynamoDB, Bedrock (mocked), Lambda

**Requirements Satisfied:** R6 (evidence cross-reference validation, hallucination controls), R9 (evidence validation stage)

**Dependencies:** T19-01, T06-05 (citation validator), T09-03 (evidence stage)

**Security Considerations:** ⚠️[SECURITY-RISK] This test verifies the hallucination control: if the AI produces conclusions without supporting evidence, those conclusions must not lead to remediation.

**Acceptance Criteria:**
1. Test scenarios:
   - Bedrock report cites evidence_id that does not exist in the evidence package → citation validation fails → report rejected
   - Bedrock report claims ffected_principals that are not in any finding → hallucination detected → report rejected
   - Bedrock report cites a quote that does not appear in any evidence item → citation validation fails → report rejected
   - Investigation report has empty evidence_citations → citation validation fails → report rejected
2. Assertions for each:
   - Investigation report has alidation_status=REJECTED
   - Safety Validation Engine assigns Level 3
   - No remediation is attempted
   - HallucinationDetected metric is emitted (for principal/resource hallucination)
   - CitationValidationError metric is emitted (for citation failures)
   - Incident is escalated with escalation_reason=investigation_rejected

**Tests Required:** 4 sub-tests; each with validation_status and Level 3 assertions

**Expected Cost Impact:** 🟡[CHARGES] Negligible (mocked Bedrock)

**Manual Verification:** Run scenario; confirm investigation report rejected; verify metrics emitted; confirm no Step Functions execution

---

### Task T19-12: Test Scenario — DLQ and Retry Behavior

**Status:** IMPLEMENTED — LIVE LAB CHECKPOINT PENDING

**Objective:** Verify that unparseable events are correctly routed to the DLQ, retained for 14 days, and that the DLQ alarm fires when depth exceeds threshold.

**Files/Components Affected:** 	ests/e2e/scenarios/test_dlq_retry.py

**AWS Services Involved:** SQS, Lambda, CloudWatch, EventBridge

**Requirements Satisfied:** R1 (parse failure handling, DLQ with 14-day retention, ParseFailure metric)

**Dependencies:** T19-01, T02-04 (DLQ), T03-01 through T03-05 (ingestion Lambdas)

**Security Considerations:** DLQ must retain messages for 14 days. DLQ must not be publicly accessible. ParseFailure metric must be emitted for each parse failure.

**Acceptance Criteria:**
1. Test scenarios:
   - Send malformed JSON event to GuardDuty ingestion Lambda → routed to DLQ → ParseFailure metric incremented
   - Send unparseable CloudTrail event → routed to DLQ → ParseFailure metric incremented
   - DLQ message retention: send message, wait, confirm message still present after 13 days (TTL test — use shortened TTL in test)
   - DLQ alarm: send 10 messages to DLQ, confirm DLQDepth alarm fires
2. Assertions:
   - DLQ contains the malformed event with original payload
   - ParseFailure CloudWatch metric incremented by 1 for each malformed event
   - DLQ message retention is 14 days (1209600 seconds)
   - TelemetryIngestionLag metric emitted when no events received for 15 minutes
   - DLQ is not publicly accessible (policy check)
   - Only platform Lambda functions can receive from DLQ

**Tests Required:** 4 sub-tests; DLQ depth assertion; metric assertion; retention period assertion

**Expected Cost Impact:** 🟡[CHARGES] Negligible

**Manual Verification:** Send test malformed event; confirm it appears in DLQ; check CloudWatch metric for ParseFailure; verify DLQ retention period

**CHECKPOINT — Phase 19 Review:** Before proceeding to Phase 20, manually verify: (1) all 12 E2E scenarios pass in the lab environment, (2) every scenario maps back to at least one requirement, (3) safety guarantees hold (no unauthorized remediation, no false resolution), (4) all failure modes are tested and handled correctly, (5) observability metrics are emitted for every scenario, (6) evidence preservation occurs for all scenarios including failures.


---

## Phase 20: Portfolio, Documentation and Demo

**Goal:** Produce the final portfolio package — architecture documentation, README, threat model, deployment instructions, demo script, and all materials needed to present CloudSec AI as a professional portfolio project.

**Danger Flags in this phase:** None (documentation and presentation only)

### Task T20-01: Create Final Architecture Diagram

**Objective:** Produce the definitive system architecture diagram showing all CloudSec AI components, data flows, and trust boundaries.

**Files/Components Affected:** docs/architecture-diagram.png, docs/architecture-diagram.drawio, docs/architecture.md

**AWS Services Involved:** None (diagram creation)

**Requirements Satisfied:** R17 (architecture documentation)

**Dependencies:** All prior phases (final architecture reflects all implemented components)

**Security Considerations:** Diagram must clearly show trust boundaries between Security Account, Workload Accounts, and Lab. Data flow arrows must show direction of information. KMS key boundaries must be visible.

**Acceptance Criteria:**
1. Architecture diagram in draw.io format (rchitecture-diagram.drawio) and PNG export (rchitecture-diagram.png)
2. Diagram includes:
   - Security Account boundary with all platform components
   - Workload Account boundary with telemetry sources (GuardDuty, Security Hub, CloudTrail, Config, VPC Flow Logs)
   - Lab Account boundary (isolated)
   - Data flow arrows between all components
   - EventBridge security bus and event flow
   - DynamoDB tables and their relationships
   - Bedrock invocation (dashed line, no direct AWS action execution)
   - Step Functions remediation workflow
   - KMS keys and encryption boundaries
   - Evidence S3 bucket with object-lock
   - Human approval API and Cognito
3. docs/architecture.md provides written explanation of the diagram

**Tests Required:** None (diagram review)

**Expected Cost Impact:** 

**Manual Verification:** Review architecture diagram; confirm all components and data flows are shown; confirm trust boundaries are clear

---

### Task T20-02: Write Project README

**Objective:** Create a comprehensive README that explains what CloudSec AI is, what problem it solves, and how to get started.

**Files/Components Affected:** README.md

**AWS Services Involved:** None

**Requirements Satisfied:** R17 (project overview)

**Dependencies:** T20-01 (architecture diagram reference)

**Security Considerations:** README must include prominent safety warnings about running automated remediation. Must state that the platform is for educational/portfolio use and should not be deployed to production without additional review.

**Acceptance Criteria:**
1. README includes:
   - Project title and one-paragraph description
   - Problem statement (why this platform exists)
   - Solution overview (what the platform does in 5-10 bullet points)
   - Architecture diagram reference (link to docs/architecture.md)
   - Technology stack table (AWS services used, purpose)
   - Quick start section (prerequisites, deployment in 5 steps)
   - Project structure overview (directory tree)
   - Safety warnings (automated remediation, AI output, lab-only simulations)
   - Links to detailed documentation (docs/)
   - License and author information
   - AWS account requirements (Security Account, Workload Account, Lab Account)
2. README is professional and polished (portfolio-ready)
3. All internal links resolve correctly

**Tests Required:** None (documentation)

**Expected Cost Impact:** 

**Manual Verification:** Read README end-to-end; confirm all links resolve; verify safety warnings are prominent

---

### Task T20-03: Write Architecture Explanation and AWS Service Justification

**Objective:** Document the architectural decisions and justify every AWS service choice.

**Files/Components Affected:** docs/architecture-decisions.md

**AWS Services Involved:** None (documentation)

**Requirements Satisfied:** R17 (architecture explanation, AWS service justification)

**Dependencies:** T20-01

**Security Considerations:** Justification must explain why serverless was chosen over EC2/EKS, why EventBridge was chosen over SQS for internal events, why DynamoDB was chosen over RDS, and why these choices improve the security posture.

**Acceptance Criteria:**
1. docs/architecture-decisions.md includes:
   - **Why serverless?** Lambda + Step Functions vs EC2/EKS (cost, scaling, attack surface)
   - **Why EventBridge?** Custom event bus for internal routing vs SQS/SNS (decoupling, filtering, fan-out)
   - **Why DynamoDB?** Single-table design for incidents/findings vs RDS (performance, scale, no infrastructure)
   - **Why Bedrock?** Managed AI vs self-hosted model (security, maintenance, cost)
   - **Why S3 with object-lock?** Forensic immutability vs EBS/RDS backups
   - **Why KMS CMKs?** Customer-managed keys vs AWS-managed (control, audit, rotation)
   - **Why Step Functions?** Workflow orchestration vs Lambda chaining (state management, retries, observability)
   - **Why API Gateway + Cognito?** Approval API vs CLI script (auth, audit, accessibility)
2. Each decision includes: context, alternatives considered, trade-offs, decision, consequences
3. Format follows ADR (Architecture Decision Record) pattern

**Tests Required:** None (documentation)

**Expected Cost Impact:** 

**Manual Verification:** Review ADR document; confirm each service choice is justified with trade-offs

---

### Task T20-04: Write Threat Model and Trust-Boundary Documentation

**Objective:** Produce a formal threat model for CloudSec AI including trust boundaries, attack surface analysis, and mitigation strategies.

**Files/Components Affected:** docs/threat-model.md

**AWS Services Involved:** None

**Requirements Satisfied:** R17 (threat model, trust-boundary documentation)

**Dependencies:** T20-01 (architecture diagram for trust boundary reference)

**Security Considerations:** Threat model must identify threats TO the platform itself (not just threats the platform detects). Must cover the AI component as a potential attack vector (prompt injection, output manipulation).

**Acceptance Criteria:**
1. docs/threat-model.md includes:
   - **Trust boundaries** (diagram showing Security Account, Workload Accounts, Lab, external attackers, AWS, Bedrock provider)
   - **Assets** (incident data, evidence, findings, baselines, knowledge base, KMS keys, IAM roles)
   - **Threat model using STRIDE:**
     - Spoofing: forged findings, fake principal ARNs, unauthorized API calls to approval API
     - Tampering: DynamoDB item modification, evidence tampering, S3 bucket policy changes
     - Repudiation: missing audit logs, deleted evidence, denied remediation execution
     - Information Disclosure: finding data leakage, Bedrock prompt leakage, cross-account data exposure
     - Denial of Service: Lambda throttling, DynamoDB throttling, Bedrock throttling, event backlog
     - Elevation of Privilege: IAM role escalation, Bedrock output manipulation, safety validation bypass
   - **Prompt injection threat model** (specific to AI component):
     - Attacker crafts CloudTrail events containing prompt injection payloads
     - Mitigation: evidence redaction, structured schema validation, citation requirements
   - **Mitigation matrix** mapping each threat to platform controls
   - **Residual risks** (accepted risks with justification)

**Tests Required:** None (documentation)

**Expected Cost Impact:** 

**Manual Verification:** Review threat model; confirm STRIDE analysis is complete; verify prompt injection mitigations are documented

---

### Task T20-05: Write IAM and Security Design Explanation

**Objective:** Document the IAM architecture, least-privilege model, and security design decisions.

**Files/Components Affected:** docs/iam-design.md

**AWS Services Involved:** None

**Requirements Satisfied:** R17 (IAM/security explanation)

**Dependencies:** T01-07 (IAM foundations), T20-04 (threat model)

**Security Considerations:** Document must explain how the platform enforces least-privilege at every layer: Lambda roles, Step Functions roles, EventBridge permissions, KMS key policies, S3 bucket policies.

**Acceptance Criteria:**
1. docs/iam-design.md includes:
   - IAM role diagram showing all roles and their trust policies
   - Permission matrix: role → allowed actions → resources
   - Least-privilege justification for each policy
   - Cross-account IAM design (Workload Account → Security Account trust)
   - KMS key policy design (which principals can use which keys)
   - S3 bucket policy design (which principals can write to which buckets)
   - EventBridge permission model (which rules can invoke which targets)
   - Cognito user pool design (groups, permissions, auth flows)
   - Principle of least-privilege violations intentionally accepted (with justification)

**Tests Required:** None (documentation)

**Expected Cost Impact:** 

**Manual Verification:** Review IAM design; confirm every role's permissions are justified; verify cross-account trust design is documented


### Task T20-06: Write Bedrock Safety Guardrail Explanation

**Objective:** Document the AI safety architecture — how CloudSec AI prevents the LLM from causing harm.

**Files/Components Affected:** docs/bedrock-safety-guardrails.md

**AWS Services Involved:** None

**Requirements Satisfied:** R6 (AI never executes AWS remediation directly, hallucination controls, evidence validation, schema validation), R9 (safety validation engine, Level 3→2→1 precedence)

**Dependencies:** T06-03, T06-05, T09-01 through T09-05

**Security Considerations:** This is the most important document for reviewers to understand why the AI component is safe. Must explain every guardrail and how they layer together.

**Acceptance Criteria:**
1. docs/bedrock-safety-guardrails.md includes:
   - **Principle: AI Never Executes** — Bedrock produces recommendations only; a deterministic safety engine decides whether to execute
   - **Guardrail 1: Strict JSON Schema** — all Bedrock output must conform to Platform Investigation Schema; malformed output is rejected
   - **Guardrail 2: Evidence Citations** — every AI conclusion must cite evidence IDs; citations are validated against actual evidence
   - **Guardrail 3: Hallucination Detection** — affected principals and resources must exist in the evidence package
   - **Guardrail 4: Approved Action Policy** — only pre-approved actions can be executed; unknown actions are Level 3
   - **Guardrail 5: Evidence Validation** — action parameters must be traceable to investigation report findings
   - **Guardrail 6: Risk Classification** — high-risk actions (high blast radius, critical resources, night-time) are automatically upgraded to Level 2
   - **Guardrail 7: Human Approval Gate** — Level 2 actions require human approval via authenticated API
   - **Guardrail 8: Redaction** — all data sent to Bedrock is redacted of sensitive information
   - **Guardrail 9: Prompt Engineering** — model is instructed to never execute code, never suggest destructive actions
   - **Defense-in-depth diagram** showing all guardrails in sequence
   - **What happens when a guardrail fails** (each failure mode and its consequence)

**Tests Required:** None (documentation)

**Expected Cost Impact:** 

**Manual Verification:** Review document; confirm every safety control is explained; verify defense-in-depth narrative is clear

---

### Task T20-07: Write Deployment Instructions (Terraform)

**Objective:** Create step-by-step deployment instructions for dev, staging, and production environments.

**Files/Components Affected:** docs/deployment.md

**AWS Services Involved:** None (documentation referencing all AWS services)

**Requirements Satisfied:** R17 (deployment instructions)

**Dependencies:** T01-01 through T01-08 (all infrastructure)

**Security Considerations:** Instructions must include explicit steps for configuring least-privilege IAM, KMS keys, and cost controls BEFORE deploying any billable resources. Must warn about HARD-TO-DELETE resources.

**Acceptance Criteria:**
1. docs/deployment.md includes:
   - Prerequisites: AWS account(s), AWS CLI, Terraform, Python, git, AWS SSO
   - Account setup: Security Account, Workload Account(s), Lab Account
   - Phase-by-phase deployment order (matching task phases 1-20)
   - Environment variable configuration (	erraform.tfvars per environment)
   - Terraform commands per phase: 	erraform init, 	erraform plan, 	erraform apply
   - Post-deployment verification steps
   - Multi-account role assumption configuration (AWS SSO)
   - Cost control setup (budgets before infrastructure)
   - Dangerous resource warnings (HARD-TO-DELETE: KMS keys, S3 object-lock, CloudTrail)
   - Rollback procedure per phase
   - Estimated deployment time per phase

**Tests Required:** None (documentation)

**Expected Cost Impact:** 

**Manual Verification:** Follow deployment instructions in a fresh account; confirm each step works; verify cost controls are set before infrastructure

---

### Task T20-08: Write Cleanup and Destroy Instructions

**Objective:** Document the complete teardown procedure for all environments, including handling HARD-TO-DELETE resources.

**Files/Components Affected:** docs/cleanup.md, scripts/cleanup-all.sh

**AWS Services Involved:** None (documentation)

**Requirements Satisfied:** R17 (cleanup instructions)

**Dependencies:** T01-02 through T01-06 (resources that are hard to delete)

**Security Considerations:** Cleanup must handle KMS key pending-deletion windows, S3 object-lock retention, and CloudTrail trails. Must warn about data loss (DynamoDB tables, evidence bucket).

**Acceptance Criteria:**
1. docs/cleanup.md includes:
   - Phase-by-phase teardown order (reverse of deployment)
   - KMS key deletion: disable key, schedule deletion (7-day wait), confirm deletion
   - S3 bucket with object-lock: suspend object-lock, delete all versions, delete bucket
   - CloudTrail: stop logging, delete trail
   - DynamoDB tables: delete tables (wait for DELETE_IN_PROGRESS)
   - EventBridge rules and custom buses: delete rules first, then bus
   - Lambda functions: delete function versions, then function
   - Step Functions: stop executions, delete state machine
   - Cleanup script scripts/cleanup-all.sh with --confirm flag and --dry-run mode
2. Estimated cleanup time per phase
3. Verification steps to confirm all resources are deleted
4. Cost savings confirmation (check AWS Billing after cleanup)

**Tests Required:** --dry-run mode works; --confirm mode requires explicit confirmation

**Expected Cost Impact:** 

**Manual Verification:** Run --dry-run; review output; execute cleanup in dev environment; confirm all resources deleted

---

### Task T20-09: Write Cost Documentation

**Objective:** Document the expected costs for each environment and provide cost optimization guidance.

**Files/Components Affected:** docs/cost-documentation.md

**AWS Services Involved:** None (documentation)

**Requirements Satisfied:** R17 (cost documentation)

**Dependencies:** All phases with cost flags (T01-02, T01-06, T03-01, T03-02, T06-01, T14-01, T17-02 through T17-06, T18-01)

**Security Considerations:** Cost documentation helps prevent surprise bills. Must include budget thresholds and cost alarm recommendations.

**Acceptance Criteria:**
1. docs/cost-documentation.md includes:
   - Cost table by service: service, dev estimate (monthly), prod estimate (monthly), cost driver
   - Total estimated monthly cost: dev (~-100), prod (~-500 depending on volume)
   - Bedrock cost breakdown: input tokens, output tokens, estimated invocations per day
   - Top 3 cost drivers: Bedrock, CloudTrail/S3 storage, DynamoDB
   - Cost optimization tips:
     - Use Claude Haiku instead of Sonnet for lower cost (with quality trade-off)
     - Reduce baseline computation frequency for low-activity accounts
     - Archive old findings to reduce DynamoDB storage
     - Use Savings Plans for consistent Lambda/Bedrock usage
   - Budget recommendations: /month (dev), /month (prod)
   - Cost alarm configuration steps
   - Per-incident cost estimate (one full investigation lifecycle)

**Tests Required:** None (documentation)

**Expected Cost Impact:** 

**Manual Verification:** Review cost table; confirm estimates match actual AWS pricing; verify budget recommendations

---

### Task T20-10: Document Known Limitations, MVP-vs-Production Differences, and Security Assumptions

**Objective:** Create an honest documentation of what the platform does not do, what differs between MVP and production, and the security assumptions on which the design relies.

**Files/Components Affected:** docs/limitations-and-assumptions.md

**AWS Services Involved:** None

**Requirements Satisfied:** R17 (known limitations, production-vs-MVP differences, security assumptions)

**Dependencies:** All prior phases

**Security Considerations:** This document is critical for responsible use — it must clearly state what the platform is NOT designed to handle.

**Acceptance Criteria:**
1. docs/limitations-and-assumptions.md includes:
   - **Known Limitations:**
     - AI investigation quality depends on evidence quality and model capability
     - Bedrock may produce hallucinated recommendations (mitigated but not eliminated)
     - Cross-account correlation requires explicit configuration
     - Behavior baselines require minimum 7 days of data for meaningful results
     - Attack simulation covers 6 scenarios only (not exhaustive)
     - Single-region deployment (multi-region requires additional configuration)
     - No real-time streaming (EventBridge near-real-time, not sub-second)
   - **MVP vs Production Differences:**
     - MVP: single Workload Account; Production: multiple Workload Accounts via AWS Organizations
     - MVP: manual baseline seeding; Production: automated 30-day historical import
     - MVP: single approver; Production: multiple approvers with RBAC
     - MVP: 30-day evidence retention; Production: 365-day retention with Glacier archive
     - MVP: no WAF on approval API; Production: WAF + rate limiting
     - MVP: dev KMS keys; Production: multi-region KMS keys with backup
   - **Security Assumptions:**
     - AWS API Gateway enforces HTTPS (no plaintext credentials in transit)
     - KMS keys are not compromised
     - Cognito user pool is properly configured with MFA
     - CloudTrail is enabled and tamper-evident in all accounts
     - EventBridge rules are not modified by attackers
     - The Safety Validation Engine is the ground truth for execution decisions
     - Human approvers are trustworthy and not compromised

**Tests Required:** None (documentation)

**Expected Cost Impact:** 

**Manual Verification:** Review document; confirm limitations are honest and complete; verify MVP-vs-production table is accurate


---
### Task T20-11: Create Screenshots and Evidence Capture Plan
**Objective:** Capture high-quality screenshots of every major platform screen and telemetry output for the project portfolio and demo walkthrough.
**Files/Components Affected:** docs/screenshots/, docs/evidence-capture-plan.md
**AWS Services Involved:** None (documentation)
**Requirements Satisfied:** R17 (portfolio artifacts)
**Dependencies:** T20-01 through T20-10 (all prior documentation), T19-01 through T19-12 (e2e tests must be passing)
**Security Considerations:** Screenshots must redact any account IDs, role ARNs, access keys, token values, and IP addresses. Use dev environment only for screenshots.
**Acceptance Criteria:**
1. docs/screenshots/ contains:
   - architecture-diagram.png (from T20-01)
   - terraform-deploy.png (terraform apply success screen)
   - guardduty-finding.png (sample GuardDuty finding)
   - eventbridge-event.png (normalized security event in DynamoDB)
   - bedrock-investigation.png (investigation report output)
   - attack-timeline.png (attack timeline visualization)
   - blast-radius.png (blast radius assessment output)
   - safety-validation.png (execution decision output)
   - human-approval.png (approval API screen)
   - verification-result.png (post-remediation verification)
   - incident-report.png (final generated report)
2. docs/evidence-capture-plan.md documents the exact steps to reproduce each screenshot from a clean dev deploy
3. All screenshots are high-resolution (1920x1080 minimum), properly redacted, and labeled with scenario name and timestamp
**Tests Required:** None (documentation)
**Expected Cost Impact:**
**Manual Verification:** Review all screenshots; confirm redaction is complete; reproduce one screenshot from clean dev environment to verify instructions
---
### Task T20-12: Configure Demo Environment Setup Script
**Objective:** Create a one-command demo environment setup script that provisions a pre-configured demo with sample data for a live presentation.
**Files/Components Affected:** scripts/setup-demo.sh, terraform/environments/demo/, docs/demo-setup.md
**AWS Services Involved:** All platform services (demo profile)
**Requirements Satisfied:** R17 (demo environment)
**Dependencies:** T01-02 through T01-08 (foundation), T18-01 (lab environment)
**Security Considerations:** Demo environment must use a dedicated AWS account or SSO role with minimal permissions. Must include --no-real-data flag to prevent accidental production data exposure. Must never deploy to the same account as production.
**Acceptance Criteria:**
1. scripts/setup-demo.sh accepts --account, --region, --duration-hours, --no-real-data flags
2. scripts/setup-demo.sh performs: terraform init, terraform apply (demo environment), seed sample findings (12 pre-built scenarios), configure CloudWatch dashboards, create demo user in Cognito
3. docs/demo-setup.md documents: prerequisites (AWS CLI, Terraform, Python 3.11), estimated setup time (15 minutes), estimated cost (~/4 hours), cleanup procedure
4. Demo environment includes pre-seeded data: 3 active incidents, 2 pending approvals, 1 completed remediation with evidence
5. scripts/setup-demo.sh --teardown performs full cleanup
6. --no-real-data flag prevents any real GuardDuty/Security Hub findings from being ingested
**Tests Required:** scripts/setup-demo.sh --dry-run produces expected resource list; full setup completes in < 20 minutes
**Expected Cost Impact:** 🟡[CHARGES] ~/4 hours (all demo resources)
**Manual Verification:** Run setup script in isolated demo account; confirm all pre-seeded data appears in dashboard; run teardown; confirm all resources deleted
---
### Task T20-13: Prepare Safe Attack Simulation Scripts for Live Demo
**Objective:** Create controlled, repeatable attack simulation scripts specifically designed for live demonstration — fast execution, predictable outcomes, zero risk to real resources.
**Files/Components Affected:** scripts/demo-attacks/, docs/demo-attack-guide.md
**AWS Services Involved:** GuardDuty (enabled), CloudTrail, IAM, S3 (demo-only resources)
**Requirements Satisfied:** R17 (safe demo attack scripts)
**Dependencies:** T18-01 through T18-04 (attack lab), T20-12 (demo environment)
**Security Considerations:** Scripts must run ONLY in the demo environment. Must include --confirm-live flag that prevents accidental execution in non-demo accounts. Must never create or modify IAM policies in real accounts. All demo IAM users must be pre-created with minimal permissions.
**Acceptance Criteria:**
1. scripts/demo-attacks/ contains:
   - 01-demo-credential-compromise.sh (creates demo IAM user, simulates sign-in from unusual location via STS GetSessionToken, cleans up user)
   - 02-demo-s3-public.sh (creates demo S3 bucket, makes it public via block-public-acls=false, triggers detection, cleans up)
   - 03-demo-security-group.sh (creates demo EC2 instance, opens SG port 0.0.0.0/0 on SSH, triggers detection, tears down instance)
   - 04-demo-cloudtrail-tamper.sh (uses demo admin role to disable CloudTrail logging, triggers detection, re-enables)
2. Each script has: --demo-only flag check, pre-flight account ID verification, estimated runtime (2-5 minutes), cleanup at end
3. docs/demo-attack-guide.md documents: expected detection time per scenario, expected incident lifecycle duration, rollback procedure
4. scripts/demo-attacks/run-all-demo.sh runs all 4 scenarios in sequence with configurable delay between each
5. Each script outputs: "DEMO ATTACK COMPLETED - checking CloudSec AI detection..." and waits for incident creation confirmation
**Tests Required:** Each script --dry-run mode lists resources to be created/deleted; full run in demo account produces expected detection within 5 minutes
**Expected Cost Impact:** 🟡[CHARGES] ~-10 total for all demo attacks (short-lived EC2, S3 storage)
**Manual Verification:** Run each script individually in demo account; confirm detection within 5 minutes; confirm cleanup succeeds; confirm no resources remain after teardown
---
### Task T20-14: Create End-to-End Demo Walkthrough Script
**Objective:** Document the complete step-by-step demo walkthrough that takes a viewer from "here is the problem" through a full incident lifecycle to "here is the remediated state and report."
**Files/Components Affected:** docs/demo-walkthrough.md
**AWS Services Involved:** None (documentation)
**Requirements Satisfied:** R17 (end-to-end demo walkthrough)
**Dependencies:** T20-01 through T20-13 (all prior demo artifacts)
**Security Considerations:** Walkthrough must not reveal any real credentials, account IDs, or production architecture details. All examples use demo-account identifiers.
**Acceptance Criteria:**
1. docs/demo-walkthrough.md is structured as a 17-step timed walkthrough:
   - Step 1 (2 min): Explain the problem — AWS accounts generate thousands of security events daily, most go uninvestigated
   - Step 2 (3 min): Show CloudSec AI architecture (T20-01 diagram) with trust boundaries
   - Step 3 (2 min): Show secure AWS environment — Security Account vs Workload Accounts
   - Step 4 (2 min): Trigger controlled incident — run scripts/demo-attacks/01-demo-credential-compromise.sh
   - Step 5 (2 min): Show telemetry — GuardDuty finding appears in Security Hub and CloudTrail
   - Step 6 (2 min): Show detection and correlation — EventBridge event, DynamoDB incident record
   - Step 7 (3 min): Show AI investigation — Bedrock investigation report with evidence references
   - Step 8 (2 min): Show evidence-backed attack timeline
   - Step 9 (2 min): Show blast radius assessment
   - Step 10 (1 min): Show risk/confidence decision
   - Step 11 (2 min): Show safety validation — execution decision output
   - Step 12 (2 min): Execute remediation — Step Functions state machine runs
   - Step 13 (2 min): Show human approval if Level 2 or 3 (demonstrate approve/reject)
   - Step 14 (2 min): Verify the fix — re-query AWS, confirm finding resolved
   - Step 15 (1 min): Show preserved evidence — S3 bucket, manifest
   - Step 16 (2 min): Show final incident report — JSON and Markdown
   - Step 17 (3 min): Explain how architecture scales to production — multi-account, longer retention, RBAC
2. Total estimated walkthrough time: 35 minutes
3. docs/demo-walkthrough.md includes: slide deck references, speaker notes for each step, common Q&A responses, troubleshooting for each step
**Tests Required:** None (documentation)
**Expected Cost Impact:**
**Manual Verification:** Perform full walkthrough with a colleague; time each step; confirm all screenshots match docs/screenshots/
---
### Task T20-15: Write Interview Explanation and Talking Points
**Objective:** Create a comprehensive set of interview talking points, common questions and answers, and a narrative that explains the CloudSec AI platform to technical and non-technical audiences.
**Files/Components Affected:** docs/interview-guide.md
**AWS Services Involved:** None (documentation)
**Requirements Satisfied:** R17 (interview explanation)
**Dependencies:** T20-01 through T20-14 (all prior documentation)
**Security Considerations:** Talking points must accurately represent security controls and not overstate AI capabilities. Must acknowledge limitations honestly.
**Acceptance Criteria:**
1. docs/interview-guide.md includes:
   - **Elevator Pitch (30 seconds):** One-paragraph explanation of what CloudSec AI does and why it matters
   - **Problem Statement (2 minutes):** Why manual security incident response doesn't scale in AWS environments
   - **Architecture Overview (5 minutes):** High-level walkthrough of the 20-phase system with emphasis on trust boundaries and safety
   - **Key Technical Decisions (5 minutes):** Why Bedrock over custom LLM, why Step Functions for remediation, why Safety Validation Engine as a separate phase
   - **Security Design (5 minutes):** Zero direct AI-to-AWS execution, human-in-the-loop for high-risk actions, evidence-backed decisions, tamper-evident logging
   - **AI Safety Approach (3 minutes):** Schema validation, evidence cross-referencing, policy checks, risk classification, execution decision engine
   - **Production Readiness (3 minutes):** Dev vs prod differences, multi-account scaling, RBAC, retention policies
   - **Cost and ROI (2 minutes):** Estimated costs, what it saves (engineer time per incident), when it pays for itself
   - **Common Technical Questions (10+ Q&A):**
     - "How do you prevent Bedrock from hallucinating dangerous actions?"
     - "What happens if the Safety Validation Engine is compromised?"
     - "How do you handle cross-account incidents?"
     - "What is your mean time to detect and remediate?"
     - "How do you verify remediation actually worked?"
     - "What happens when Bedrock is down?"
     - "How do you prevent automated remediation from making things worse?"
   - **Non-Technical Explanation (2 minutes):** For executives and non-security stakeholders
2. Interview guide includes red flags: what NOT to say, common misconceptions to avoid
3. Interview guide includes demo script references for each section
**Tests Required:** None (documentation)
**Expected Cost Impact:**
**Manual Verification:** Present the elevator pitch and one technical Q&A to a colleague; confirm accuracy and clarity

---
### Task T20-16: Write Troubleshooting Guide
**Objective:** Create a comprehensive troubleshooting guide covering common deployment failures, runtime errors, detection gaps, and remediation issues.
**Files/Components Affected:** docs/troubleshooting.md
**AWS Services Involved:** None (documentation)
**Requirements Satisfied:** R17 (troubleshooting guide)
**Dependencies:** T20-01 through T20-15 (all prior documentation)
**Security Considerations:** Troubleshooting steps must not suggest bypassing security controls, disabling GuardDuty/Security Hub, or using broad IAM permissions as a workaround.
**Acceptance Criteria:**
1. docs/troubleshooting.md is organized by category:
   - **Terraform Deployment Failures:**
     - "Error: no existing key found" (KMS key not provisioned first) — fix: run T01-06 before other modules
     - "Error: lock timeout" (DynamoDB state lock not released) — fix: force-unlock with terraform force-unlock <lock-id>
     - "Error: assumed role has no access" (SSO role not configured) — fix: verify T01-03 SSO configuration
   - **Detection and Ingestion Failures:**
     - "GuardDuty findings not appearing in DynamoDB" — check EventBridge rule, Lambda logs, IAM permissions
     - "CloudTrail events not being parsed" — check S3 event notification, Lambda trigger, log format compatibility
     - "Security Hub findings dropped" — check Security Hub enablement, detector status, region coverage
   - **Correlation Engine Issues:**
     - "Findings not being correlated into incidents" — check time window configuration (T04-05), partition key schema
     - "Duplicate incidents created" — check idempotency key logic (T10-02), event deduplication
   - **Bedrock Investigation Failures:**
     - "Bedrock timeout" — check T06-06 retry/timeout handler, model availability in region
     - "Malformed investigation report" — check schema validation (T06-05), prompt template
     - "Bedrock returns hallucinated recommendations" — check evidence cross-reference validator, schema enforcement
   - **Safety Validation and Remediation Failures:**
     - "Remediation not executing after Safety Validation passes" — check Step Functions state machine, execution role permissions
     - "Human approval request never received" — check SNS topic subscription, API Gateway integration
     - "Remediation executed but verification fails" — check verification Lambda (T13-01), AWS API call timing
   - **Evidence and Reporting Failures:**
     - "Evidence not being preserved to S3" — check S3 bucket permissions, KMS key access, bucket policy
     - "Incident report not generated" — check report Lambda, template rendering, S3 write permissions
   - **Observability and Alerting Issues:**
     - "CloudWatch alarms not firing" — check metric math expressions, alarm thresholds, evaluation periods
     - "DLQ messages not being retried" — check retry Lambda, dead letter queue configuration, error logging
2. Each troubleshooting entry includes: symptom, root cause, diagnostic steps (exact CLI commands and CloudWatch log queries), fix, and prevention
3. docs/troubleshooting.md includes an escalation path: self-serve troubleshooting -> dev team -> platform team -> AWS support
4. docs/troubleshooting.md includes a "Known Issues" section with current unresolved items and workarounds
**Tests Required:** None (documentation)
**Expected Cost Impact:**
**Manual Verification:** Simulate one troubleshooting scenario (e.g., disable EventBridge rule); follow docs/troubleshooting.md steps; confirm fix works

---
## Requirement Traceability

This table maps each requirement to its design component, implementation tasks, and test tasks.

| Req | Requirement Summary | Design Component | Implementation Tasks | Test Tasks |
|-----|-------------------|-----------------|---------------------|------------|
| R1 | Security telemetry ingestion from multiple AWS sources | Telemetry Ingestion Layer | T03-01 through T03-06 | T19-02, T19-10, T19-12 |
| R2 | Centralized incident platform with state management | Core Incident Platform | T01-01 through T01-08, T02-01 through T02-08 | T19-02 through T19-12 |
| R3 | Event correlation and grouping | Correlation Engine | T04-01 through T04-06 | T19-02, T19-09 |
| R4 | AI-driven investigation using Bedrock with evidence cross-referencing | AI Investigation Engine | T06-01 through T06-06 | T19-05, T19-06 |
| R5 | Attack timeline reconstruction with MITRE ATT&CK mapping | Attack Reconstruction | T07-01 through T07-05 | T19-02, T19-04 |
| R6 | Blast radius assessment using IAM Policy Simulator | Blast Radius Engine | T08-01 through T08-05 | T19-02, T19-04 |
| R7 | Safety Validation Engine preventing direct Bedrock-to-AWS execution | Safety Validation Engine | T09-01 through T09-05 | T19-03, T19-04, T19-07 |
| R8 | Automated remediation through Step Functions with idempotency | Remediation Framework | T10-01 through T10-05 | T19-02, T19-07 |
| R9 | Human approval workflow for high-risk remediation | Human Approval Layer | T12-01 through T12-04 | T19-03 |
| R10 | Post-remediation verification with re-query and escalation | Verification Engine | T13-01 through T13-04 | T19-02, T19-08 |
| R11 | Evidence preservation with tamper-evident storage | Evidence Preservation | T14-01 through T14-05 | T19-02, T19-04 |
| R12 | Automated incident reporting (JSON, Markdown, executive summary) | Incident Reporting | T15-01 through T15-04 | T19-02, T19-06 |
| R13 | Knowledge base from verified incidents with PII redaction | Knowledge Base | T16-01 through T16-03 | T19-11 |
| R14 | Structured logging and observability | Observability | T17-01 through T17-06 | T19-12 |
| R15 | Safe attack simulation environment | Attack Lab | T18-01 through T18-04 | T19-01 through T19-12 |
| R16 | Comprehensive end-to-end testing | E2E Test Suite | T19-01 through T19-12 | T19-01 through T19-12 |
| R17 | Project portfolio, documentation, and demo | Portfolio and Demo | T20-01 through T20-16 | N/A (documentation) |
| R18 | Behavior baseline computation and anomaly detection | Behavior Baseline | T05-01 through T05-04 | T19-11 |

## Security-Critical Task Index

Tasks categorized by security-critical dimension.

| Category | Task IDs |
|----------|----------|
| **IAM Changes** | T01-07, T01-08, T03-01, T03-02, T03-05, T07-04, T08-01 through T08-05, T10-01, T11-01 through T11-06, T12-01, T14-01 |
| **KMS** | T01-06, T02-01, T02-02, T14-01, T15-04 |
| **Cross-Account Access** | T01-03, T03-04, T07-04, T08-01 through T08-03, T19-10 |
| **Bedrock** | T06-01 through T06-06, T16-01 through T16-03, T19-05, T19-06 |
| **Automated Remediation** | T09-01 through T09-05, T10-01 through T10-05, T11-01 through T11-06, T13-01 through T13-04 |
| **Human Approval** | T12-01 through T12-04, T09-04, T09-05 |
| **Evidence Retention** | T14-01 through T14-05, T15-04, T16-01 |
| **Potential AWS Charges** | T01-02, T01-06, T02-01, T02-02, T02-07, T03-01 through T03-06, T05-01, T05-02, T06-01 through T06-06, T08-01, T10-01, T12-01, T14-01, T15-04, T16-01, T17-02 through T17-06, T18-01, T20-12, T20-13 |
| **Resources Hard to Delete** | T01-06 (KMS keys), T02-01 (DynamoDB tables), T02-07 (SNS topics), T03-03 (CloudTrail trails), T14-01 (S3 buckets with versioning), T18-01 (isolated lab) |

## Cost-Creating Task Index

Tasks that enable or deploy billable AWS services.

| Task ID | Service(s) | Cost Driver |
|---------|-----------|-------------|
| T01-02 | S3 | Backend state bucket (minimal, ~$0.01/month storage only) |
| T01-06 | KMS | Customer-managed keys (~/key/year) |
| T02-01 | DynamoDB | Incident table (on-demand) |
| T02-02 | DynamoDB | Findings table (on-demand) |
| T02-07 | SNS | Notification topics |
| T03-01 | GuardDuty, Lambda, EventBridge | GuardDuty per-finding, Lambda invocations |
| T03-02 | Security Hub, Lambda, EventBridge | Security Hub per-finding, Lambda invocations |
| T03-03 | CloudTrail | Organization trail, S3 storage |
| T03-04 | CloudTrail, Lambda, S3 | CloudTrail log parsing |
| T03-05 | AWS Config, Lambda, S3 | Config recorder, Lambda invocations |
| T03-06 | VPC Flow Logs, S3, Security Lake | Flow log storage, Security Lake ingestion |
| T05-01 | DynamoDB | Baselines table (on-demand) |
| T05-02 | Lambda, DynamoDB | Baseline computation invocations |
| T06-01 through T06-06 | Bedrock, Lambda, SSM | Bedrock token costs (primary cost driver), Lambda invocations |
| T08-01 | IAM Access Analyzer, Lambda | Policy simulation calls |
| T10-01 | Step Functions | State machine executions |
| T12-01 | API Gateway, Cognito, Lambda | Approval API requests, Cognito user pool |
| T14-01 | S3, KMS | Evidence storage, encryption |
| T15-04 | S3, SNS | Report delivery storage and notifications |
| T16-01 | Bedrock Knowledge Bases, S3 | Knowledge base ingestion and retrieval |
| T17-02 through T17-06 | CloudWatch | Alarms, dashboards, custom metrics |
| T18-01 | EC2, GuardDuty, Security Hub, KMS | Isolated lab resources |
| T20-12 | All platform services | Demo environment (time-limited) |
| T20-13 | EC2, S3, IAM, GuardDuty | Demo attack resources (short-lived) |

## Manual Review Checkpoints

Tasks after which manual review is required before proceeding to the next phase.

| Checkpoint | Phase | Task(s) Completed | What to Review |
|------------|-------|-------------------|---------------|
| 1 | Phase 2 | T02-01 through T02-08 | Verify DynamoDB schema supports all event types; confirm EventBridge bus isolation; test DLQ delivery |
| 2 | Phase 3 | T03-01 through T03-06 | Verify all telemetry sources produce normalized events in DynamoDB; confirm no ingestion gaps; check CloudTrail log format |
| 3 | Phase 5 | T05-01 through T05-04 | Review baseline computation accuracy; validate anomaly detection thresholds; confirm baseline table size is manageable |
| 4 | Phase 9 | T09-01 through T09-05 | CRITICAL: Review Approved Action Policy (T09-01); verify Safety Validation Engine rejects all test-dangerous actions; confirm execution decision logic is correct before any remediation code is written |
| 5 | Phase 13 | T13-01 through T13-04 | Verify post-remediation re-query logic; test resolve/escalate decision; confirm all verification paths are covered |
| 6 | Phase 19 | T19-01 through T19-12 | Review all 12 e2e test results; confirm all pass; verify no production data is used; review edge case coverage |

## MVP Implementation Path

Minimum ordered subset of existing tasks to demonstrate ONE complete end-to-end incident lifecycle (Compromised IAM Credential).

| Order | Task ID | Description | Lifecycle Stage |
|-------|---------|-------------|-----------------|
| 1 | T01-01 | Establish Repository Structure | Foundation |
| 2 | T01-02 | Configure Terraform Backend | Foundation |
| 3 | T01-03 | Configure Providers and Auth | Foundation |
| 4 | T01-06 | Deploy KMS Foundation | Foundation |
| 5 | T01-07 | Establish IAM Foundations | Foundation |
| 6 | T02-01 | Create Incident Table | Core Platform |
| 7 | T02-03 | Deploy EventBridge Security Bus | Core Platform |
| 8 | T02-05 | Define Internal Event Schema | Core Platform |
| 9 | T02-08 | Deploy EventBridge Rules | Core Platform |
| 10 | T03-01 | GuardDuty Ingestion | Telemetry |
| 11 | T03-03 | Organization-Level CloudTrail | Telemetry |
| 12 | T03-04 | CloudTrail Log Parser | Telemetry |
| 13 | T04-02 | Principal ARN Correlation | Correlation |
| 14 | T04-06 | Incident Grouping | Correlation |
| 15 | T06-01 | Configure Bedrock Access | AI Investigation |
| 16 | T06-02 | Evidence Packaging | AI Investigation |
| 17 | T06-03 | Investigation Report Schema | AI Investigation |
| 18 | T06-04 | Bedrock Investigation Lambda | AI Investigation |
| 19 | T06-05 | Schema Validation | AI Investigation |
| 20 | T06-06 | Retry and Timeout Handler | AI Investigation |
| 21 | T07-01 | Timeline Reconstruction | Attack Reconstruction |
| 22 | T07-02 | Attack-Stage Classification | Attack Reconstruction |
| 23 | T07-03 | MITRE ATT&CK Mapping | Attack Reconstruction |
| 24 | T07-05 | Timeline Integration into Report | Attack Reconstruction |
| 25 | T08-01 | IAM Policy Simulator Integration | Blast Radius |
| 26 | T08-02 | Static Policy Fallback | Blast Radius |
| 27 | T08-05 | Blast Radius Risk Scoring | Blast Radius |
| 28 | T09-01 | Define Approved Action Policy | Safety Validation |
| 29 | T09-02 | Schema Validation Stage | Safety Validation |
| 30 | T09-03 | Evidence Validation Stage | Safety Validation |
| 31 | T09-04 | Policy Validation and Risk Classification | Safety Validation |
| 32 | T09-05 | Execution Decision Engine | Safety Validation |
| 33 | T10-01 | Deploy Remediation Step Functions | Remediation |
| 34 | T10-02 | Implement Idempotency | Remediation |
| 35 | T10-04 | Failure Handling and Rollback | Remediation |
| 36 | T10-05 | Verification Hooks | Remediation |
| 37 | T11-01 | Playbook 1: Compromised IAM Credential | Playbooks |
| 38 | T12-01 | Deploy Approval API | Human Approval |
| 39 | T12-02 | Approval Expiration and Decisions | Human Approval |
| 40 | T13-01 | Post-Remediation State Re-Query | Verification |
| 41 | T13-02 | Finding Re-Check | Verification |
| 42 | T13-03 | Resolve or Escalate Decision | Verification |
| 43 | T13-04 | Deploy Verification Lambda | Verification |
| 44 | T14-01 | Deploy Evidence S3 Bucket | Evidence |
| 45 | T14-02 | Evidence Manifest Generation | Evidence |
| 46 | T14-04 | Remediation History Storage | Evidence |
| 47 | T15-01 | JSON Report Generator | Reporting |
| 48 | T15-02 | Markdown Report Generator | Reporting |
| 49 | T15-03 | Executive Summary Generation | Reporting |
| 50 | T15-04 | Deploy Report Delivery Pipeline | Reporting |
| 51 | T18-02 | Build Simulation Scenarios (credential compromise) | Attack Lab |
| 52 | T19-01 | E2E Test Framework | Testing |
| 53 | T19-02 | Test Successful Automatic Remediation | Testing |

## Full Platform Path

Remaining task IDs needed to expand from the MVP to the complete CloudSec AI platform. Listed in dependency order.

| Order | Task ID | Description | Expansion |
|-------|---------|-------------|-----------|
| 1 | T01-04 | Dev Environment and Tooling | Foundation |
| 2 | T01-05 | Naming and Tagging Standards | Foundation |
| 3 | T01-08 | Cost Controls and Budgets | Foundation |
| 4 | T02-02 | Findings Table | Core Platform |
| 5 | T02-04 | Dead Letter Queue | Core Platform |
| 6 | T02-06 | Incident State Machine | Core Platform |
| 7 | T02-07 | SNS Notification Topics | Core Platform |
| 8 | T03-02 | Security Hub Ingestion | Telemetry |
| 9 | T03-05 | AWS Config Ingestion | Telemetry |
| 10 | T03-06 | VPC Flow Logs Ingestion | Telemetry |
| 11 | T04-01 | Finding Correlation Data Access | Correlation |
| 12 | T04-03 | Source IP Correlation | Correlation |
| 13 | T04-04 | Resource ARN Correlation | Correlation |
| 14 | T04-05 | Time-Window Logic | Correlation |
| 15 | T05-01 | Baselines Table | Behavior Baseline |
| 16 | T05-02 | Baseline Computation Lambda | Behavior Baseline |
| 17 | T05-03 | Scheduled Baseline Computation | Behavior Baseline |
| 18 | T05-04 | Anomaly Detection Logic | Behavior Baseline |
| 19 | T07-04 | Cross-Account Labeling | Attack Reconstruction |
| 20 | T08-03 | Role Assumption Path Analysis | Blast Radius |
| 21 | T08-04 | Sensitive Resource Classification | Blast Radius |
| 22 | T10-03 | Execution Tracking and Audit | Remediation |
| 23 | T11-02 | Playbook 2: Security Group Change | Playbooks |
| 24 | T11-03 | Playbook 3: Public S3 Exposure | Playbooks |
| 25 | T11-04 | Playbook 4: Compromised EC2 | Playbooks |
| 26 | T11-05 | Playbook 5: CloudTrail Tampering | Playbooks |
| 27 | T11-06 | Playbook 6: IAM Privilege Escalation | Playbooks |
| 28 | T12-03 | Self-Approval Prevention | Human Approval |
| 29 | T12-04 | Step Functions Callback Integration | Human Approval |
| 30 | T14-03 | Configuration Snapshot Capture | Evidence |
| 31 | T14-05 | AI Analysis and Verification Results Storage | Evidence |
| 32 | T16-01 | Knowledge Base Ingestion | Knowledge Base |
| 33 | T16-02 | PII Redaction Engine | Knowledge Base |
| 34 | T16-03 | Knowledge Base Query Patterns | Knowledge Base |
| 35 | T17-01 | Structured Logging | Observability |
| 36 | T17-02 | Lambda Failure Metrics and Alarms | Observability |
| 37 | T17-03 | Step Functions Failure Metrics | Observability |
| 38 | T17-04 | Bedrock Failure Metrics | Observability |
| 39 | T17-05 | Failed Remediation Metrics | Observability |
| 40 | T17-06 | CloudWatch Dashboards | Observability |
| 41 | T18-01 | Isolated Lab Environment | Attack Lab |
| 42 | T18-02 | Build All 6 Simulation Scenarios | Attack Lab |
| 43 | T18-03 | Simulation Orchestration Script | Attack Lab |
| 44 | T18-04 | Lab Operations Documentation | Attack Lab |
| 45 | T19-03 through T19-12 | All remaining E2E test scenarios | Testing |
| 46 | T20-01 through T20-16 | Portfolio, Documentation and Demo | Documentation |

## Notes

1. All tasks must be implemented sequentially within each phase. Tasks with cross-phase dependencies (shown in the dependency graph) may be deferred until their prerequisites are complete.
2. The MVP Implementation Path (53 tasks) should be completed before starting any Full Platform Path tasks. This ensures a working end-to-end lifecycle before expanding scope.
3. Six manual review checkpoints are placed at Phases 2, 3, 5, 9, 13, and 19. Phase 9 (Safety Validation Engine) is the most critical — no remediation code should be written until the Safety Validation Engine has been reviewed and validated.
4. Cost documentation in T20-09 should be reviewed and updated after each phase completes, as cost estimates will change as the platform grows.
5. Terraform destroy guidance in T20-08 must be tested in a dev environment before being relied upon for production cleanup. KMS keys require a 7-day deletion window and cannot be force-deleted.
6. The demo environment (T20-12) must never share an AWS account with production. All demo attack scripts (T20-13) include account verification safeguards.
7. Bedrock is never given direct AWS API execution permissions. The Safety Validation Engine (Phase 9) is the sole gatekeeper for all remediation execution decisions.
8. All evidence preservation (Phase 14) uses KMS encryption and S3 bucket versioning. Evidence retention defaults are 30 days for dev and 365 days for production.
9. Human approval is enforced for all Level 2 and Level 3 remediation actions. Self-approval is prevented by design (T12-03).
10. Cross-account correlation (T07-04, T19-10) requires explicit Workload Account configuration and AWS Organizations access.
11. The implementation plan is designed for a single-region deployment. Multi-region expansion requires additional configuration not covered in this plan.
12. All IAM changes must go through code review before deployment. No IAM changes should be made directly in the AWS Console.
13. The attack lab (Phase 18) is for testing only. Attack simulation must never be run in a production environment.
