
# CloudSec AI — Technical Design Document

> **Feature:** `cloudsec-ai`
> **Workflow:** Requirements-First
> **Status:** Draft — Pending Review
> **Requirements Source:** `.kiro/specs/cloudsec-ai/requirements.md`

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Components and Interfaces](#components-and-interfaces)
4. [Data Models](#data-models)
5. [EventBridge Event Schemas](#5-eventbridge-event-schemas)
6. [Cross-Account IAM Architecture](#6-cross-account-iam-architecture)
7. [Least-Privilege IAM Model](#7-least-privilege-iam-model)
8. [KMS and Encryption Architecture](#8-kms-and-encryption-architecture)
9. [AI Investigation Engine](#9-ai-investigation-engine)
10. [Platform Investigation Schema](#10-platform-investigation-schema)
11. [Hallucination and Evidence-Validation Controls](#11-hallucination-and-evidence-validation-controls)
12. [Attack Timeline Reconstruction](#12-attack-timeline-reconstruction)
13. [Blast Radius Analysis](#13-blast-radius-analysis)
14. [Safety Validation Engine](#14-safety-validation-engine)
15. [Step Functions Workflow Designs](#15-step-functions-workflow-designs)
16. [Human Approval Workflow](#16-human-approval-workflow)
17. [Remediation Playbook Designs](#17-remediation-playbook-designs)
18. [Idempotency Strategy](#18-idempotency-strategy)
19. [Rollback and Recovery Strategy](#19-rollback-and-recovery-strategy)
20. [Verification Engine](#20-verification-engine)
21. [Forensic Evidence Architecture](#21-forensic-evidence-architecture)
22. [Incident Knowledge Base](#22-incident-knowledge-base)
23. [Incident Reporting Architecture](#23-incident-reporting-architecture)
24. [Observability and Failure Handling](#24-observability-and-failure-handling)
25. [Behavior Baseline System](#25-behavior-baseline-system)
26. [Correlation Engine Design](#26-correlation-engine-design)
27. [Terraform Module Architecture](#27-terraform-module-architecture)
28. [Testing Architecture](#28-testing-architecture)
29. [Safe Attack-Simulation Architecture](#29-safe-attack-simulation-architecture)
30. [Development vs. Production Architecture](#30-development-vs-production-architecture)
31. [Cost Estimate](#31-cost-estimate)
32. [Correctness Properties](#correctness-properties)
33. [Error Handling](#error-handling)
34. [Testing Strategy](#testing-strategy)
35. [Traceability Matrix](#35-traceability-matrix)

---

## Overview

CloudSec AI is an AWS-native, serverless security operations platform that automates the complete incident response lifecycle across an AWS Organizations multi-account estate. The platform ingests security signals, correlates them into incidents, investigates them with Amazon Bedrock, validates and executes remediations through a deterministic safety layer, verifies success, and produces AI-authored incident reports — all without a human in the loop for Level 1 actions, and with a structured approval workflow for Level 2.

### Lifecycle Stages

```
Detect → Correlate → Investigate → Blast Radius → Safety Check → Contain/Fix → Verify → Report
```

### Design Principles

1. **AI advises, determinism decides.** Bedrock produces structured JSON recommendations. No Bedrock output ever directly calls an AWS API. All execution flows through the Safety Validation Engine and versioned Step Functions playbooks.
2. **Forensic integrity first.** Every artifact is immutable (S3 Object Lock in production), encrypted (KMS CMK), versioned, and traceable to an Incident ID.
3. **Least privilege everywhere.** Every Lambda and Step Functions execution role contains only the specific API actions it requires. No `*` actions permitted.
4. **Separation of concerns.** The Security Account owns all platform infrastructure. Workload Accounts expose only scoped read and remediation cross-account roles.
5. **Config-driven, not code-driven.** Environment differences (dev vs. prod) are expressed in `.tfvars` files and SSM parameters, not in code branches.
6. **Observable by default.** Every transition emits a structured CloudWatch metric. Every Lambda emits structured JSON logs with `incident_id` correlation.

### Scope of MVP

The MVP targets a two-account layout:
- **Security Account** — hosts all platform infrastructure
- **Workload Account (1)** — monitored account with `CloudSecAI-ReadRole` and `CloudSecAI-RemediationRole`

The architecture supports transparent expansion to full AWS Organizations without code changes — only Terraform variable updates and role deployments in new accounts.

---

## Architecture

### 2.1 High-Level Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│  WORKLOAD ACCOUNT(S)                                                             │
│                                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │  GuardDuty   │  │ Security Hub │  │  CloudTrail  │  │  VPC Flow Logs   │   │
│  │  (findings)  │  │  (findings)  │  │(mgmt events) │  │  → Security Lake │   │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └────────┬─────────┘   │
│         │                 │                  │                    │             │
│         └─────────────────┴──────────────────┴────────────────────┘             │
│                                   │ (Org-level EventBridge / S3)                │
└───────────────────────────────────┼────────────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────────────┐
│  SECURITY ACCOUNT                                                                │
│                                                                                  │
│  ┌──────────────────────────────────────────────────────────────────────────┐   │
│  │  TELEMETRY INGESTION LAYER                                                │   │
│  │  EventBridge Custom Bus (cloudsec-events)                                 │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────────┐  │   │
│  │  │  GD Rule    │  │  SH Rule    │  │  CT Rule    │  │  Anomaly Rule  │  │   │
│  │  │  → Lambda   │  │  → Lambda   │  │  → Lambda   │  │  → Lambda      │  │   │
│  │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └───────┬────────┘  │   │
│  │         └────────────────┴────────────────┴─────────────────┘            │   │
│  │                                   │                                        │   │
│  │                          SQS DLQ (ParseFailure)                            │   │
│  └──────────────────────────────────┬─────────────────────────────────────┘   │
│                                     │                                           │
│  ┌──────────────────────────────────▼─────────────────────────────────────┐   │
│  │  CORRELATION ENGINE                                                       │   │
│  │  Correlation Lambda ←── DynamoDB Streams ──→ Open Incidents Index        │   │
│  └──────────────────────────────────┬─────────────────────────────────────┘   │
│                                     │                                           │
│  ┌──────────────────────────────────▼─────────────────────────────────────┐   │
│  │  INCIDENT LIFECYCLE (Step Functions Standard Workflow)                    │   │
│  │  OPEN → INVESTIGATING → REMEDIATING → VERIFYING → RESOLVED/ESCALATED    │   │
│  └──────────────────────────────────┬─────────────────────────────────────┘   │
│         │                           │                          │                │
│  ┌──────▼──────┐         ┌──────────▼──────────┐  ┌──────────▼───────────┐   │
│  │  Behavior   │         │  AI Investigation    │  │  Blast Radius        │   │
│  │  Baseline   │         │  Engine (Bedrock)    │  │  Analyzer (IAM Sim)  │   │
│  └─────────────┘         └──────────┬──────────┘  └──────────────────────┘   │
│                                     │                                           │
│  ┌──────────────────────────────────▼─────────────────────────────────────┐   │
│  │  SAFETY VALIDATION ENGINE (deterministic — no AI)                        │   │
│  │  Level 1 (auto) / Level 2 (approval) / Level 3 (recommend only)          │   │
│  └──────────────────────────────────┬─────────────────────────────────────┘   │
│                    │                │                    │                      │
│         ┌──────────▼──┐  ┌─────────▼───────┐  ┌────────▼─────────────────┐  │
│         │  Level 1:   │  │  Level 2:        │  │  Level 3:               │  │
│         │  Auto-exec  │  │  Human Approval  │  │  Report only             │  │
│         └──────┬──────┘  └────────┬─────────┘  └──────────────────────────┘  │
│                └───────────────────┘                                            │
│                          │                                                      │
│  ┌───────────────────────▼────────────────────────────────────────────────┐   │
│  │  REMEDIATION PLAYBOOKS (Step Functions — one per playbook)               │   │
│  │  cloudsec-remediation-{1..6}  → Lambda → Cross-account AssumeRole       │   │
│  └───────────────────────┬────────────────────────────────────────────────┘   │
│                          │                                                      │
│  ┌───────────────────────▼────────────────────────────────────────────────┐   │
│  │  VERIFICATION ENGINE                                                      │   │
│  │  Per-playbook verification Lambda → RESOLVED or ESCALATED               │   │
│  └───────────────────────┬────────────────────────────────────────────────┘   │
│                          │                                                      │
│  ┌───────────────────────▼────────────────────────────────────────────────┐   │
│  │  REPORTING ENGINE (Bedrock narrative + structured data)                   │   │
│  │  JSON + Markdown → Forensic Evidence Package (S3)                        │   │
│  └────────────────────────────────────────────────────────────────────────┘   │
│                                                                                  │
│  SHARED INFRASTRUCTURE                                                           │
│  ┌────────────────┐  ┌───────────────┐  ┌─────────────────┐  ┌────────────┐  │
│  │  DynamoDB      │  │  S3 Forensic  │  │  Knowledge Base │  │  CloudWatch│  │
│  │  (incidents,   │  │  Bucket       │  │  DynamoDB       │  │  Alarms +  │  │
│  │   baselines,   │  │  (Object Lock)│  │                 │  │  Dashboard │  │
│  │   decisions)   │  └───────────────┘  └─────────────────┘  └────────────┘  │
│  └────────────────┘                                                             │
└────────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Account Boundary and Trust Model

```
Security Account (centralizes all platform infra)
│
├── Trusts: CloudSecAI-ReadRole in each Workload Account
├── Trusts: CloudSecAI-RemediationRole in each Workload Account
└── Owns: All EventBridge buses, DynamoDB tables, S3, Step Functions, Lambda

Workload Account(s)
├── CloudSecAI-ReadRole  → trusted by Security Account ID only (read-only)
└── CloudSecAI-RemediationRole → trusted by Remediation SFN exec role ARN only

Lab Account (isolated)
├── No trust relationship with Security Account
└── Used only for attack simulation scripts
```

### 2.3 Key Architectural Decisions

#### Decision 1: EventBridge Custom Bus vs. Default Bus

**Choice:** Custom bus named `cloudsec-events`.

**Rationale:** The default EventBridge bus carries all AWS service events from the account. A custom bus gives explicit control over which sources can publish, enables a dedicated resource policy that restricts publishers to specific Lambda roles and cross-account event forwarding from Workload Accounts, and isolates platform metrics (rule invocation counts, failed deliveries) from account-wide noise.

**Alternative considered:** Default bus with tight event patterns. Rejected because resource policies cannot be applied to the default bus, and cross-account event publishing to the default bus requires looser trust grants.

**Security implication:** The custom bus resource policy explicitly lists allowed publisher ARNs, preventing unexpected event injection.

**Failure mode:** If the bus is unavailable, ingestion Lambdas fall back to direct SQS enqueue into the correlation queue. Events are not lost.

**Interview note:** Custom EventBridge buses are the correct pattern for multi-source, multi-consumer internal event routing within a platform. They enable dead-letter queues per rule, per-rule invocation metrics, and archive/replay capabilities that the default bus does not expose on a per-rule basis.

---

#### Decision 2: DynamoDB Multi-Table Design

**Choice:** Separate DynamoDB tables for each entity class.

**Tables:**
- `cloudsec-incidents` — Incident records
- `cloudsec-findings` — raw Finding payloads
- `cloudsec-correlation-decisions` — CorrelationDecision records
- `cloudsec-open-incidents-index` — Correlation Engine lookup index
- `cloudsec-behavior-baselines` — principal baseline profiles
- `cloudsec-remediation-decisions` — Safety Validation audit records
- `cloudsec-approval-tokens` — Level 2 approval token state
- `cloudsec-knowledge-base` — confirmed resolved incidents
- `cloudsec-account-inventory` — monitored account registry

**Rationale:** Single-table DynamoDB design optimizes for a single application accessing all entities together. CloudSec AI is a pipeline where different engines (Correlation, Investigation, Safety Validation, Verification) each access entirely separate entity classes with different access patterns, throughputs, TTLs, and encryption keys. Separate tables allow per-table CMKs (required by Req 16.9), independent capacity planning, independent TTL policies, and independent backup strategies.

**Alternative considered:** Single-table with composite keys. Rejected because it would require a shared CMK (violating Req 16.9), and access pattern analysis showed no cross-entity joins at query time — each service reads and writes only its own entity class.

**Security implication:** Per-table CMKs ensure that a compromised key affects only one entity class, not all incident data.

**Interview note:** The rule "always use single-table DynamoDB" is a simplification. It applies when a single application accesses multiple related entities together. When entities are accessed by separate microservices independently, separate tables with separate CMKs is the correct security-first choice.

---

#### Decision 3: Step Functions Standard vs. Express Workflows

**Choice:** Standard Workflows for the Incident Lifecycle orchestrator and all Remediation Playbooks. Express Workflows for the Telemetry Ingestion processing pipeline.

**Rationale:**
- Standard Workflows persist execution state, support exactly-once execution semantics, allow human approval waits (`.waitForTaskToken`), and can pause for up to one year — required for the 4-hour approval window and multi-stage incident lifecycle.
- Express Workflows are high-throughput and cost-effective at-least-once execution for the ingestion pipeline where throughput can reach thousands of events/minute and each flow completes in seconds.

**Alternative considered:** Lambda-chained state via SQS for the lifecycle. Rejected because it loses execution history, makes debugging harder, and requires hand-rolling retry/backoff logic that Step Functions provides natively.

**Failure mode:** Standard Workflows bill per state transition; a long-running P4 incident with many transitions could accumulate cost. Mitigation: P3/P4 incidents use a compact state machine with fewer states.

**Interview note:** The `.waitForTaskToken` pattern is the correct way to implement human-in-the-loop approval in Step Functions. The task emits a token, pauses execution, and resumes when the approval Lambda calls `SendTaskSuccess` or `SendTaskFailure` with that token. This avoids polling and enables the 4-hour timeout via `HeartbeatSeconds`.

---

#### Decision 4: Bedrock Model Selection

**Choice:** Anthropic Claude 3.5 Sonnet (configurable via SSM parameter, not hard-coded).

**Rationale:** Claude 3.5 Sonnet offers the best balance of instruction-following accuracy, structured JSON output fidelity, context window size (200K tokens, needed for large evidence bundles), and cost for analytical tasks. Its function-calling and structured output modes reduce schema validation failures. The model ID is stored in SSM Parameter Store so it can be changed without code deployment.

**Alternative considered:** Claude 3 Haiku for cost savings. Rejected for the Investigation Engine because hallucination rates on complex multi-document security analysis are measurably higher for smaller models. Haiku is acceptable for the Reporting Engine's narrative generation sections.

**Security implication:** The Bedrock IAM role grants `bedrock:InvokeModel` only for the configured model ARN. If the SSM parameter is changed to a new model, the IAM policy must be updated via Terraform — intentional friction that prevents unauthorized model swaps.

---

#### Decision 5: Lambda vs. ECS for Long-Running Investigation

**Choice:** Lambda with a 15-minute timeout for the AI Investigation Engine.

**Rationale:** A typical evidence bundle assembly + Bedrock invocation (with up to 3 retries, 30s timeout each) completes well within 3–4 minutes. Lambda at 3008 MB RAM is sufficient and avoids the cold-start overhead, VPC attachment complexity, and container image management of ECS Fargate. Lambda also benefits from native IAM execution roles without instance profile plumbing.

**Alternative considered:** ECS Fargate for tasks that might exceed Lambda limits. Retained as the escape hatch: if evidence bundles grow beyond 6 MB (Lambda payload limit), the Investigation Engine can offload evidence to S3 and pass an S3 reference to the Bedrock invocation.

**Failure mode:** Lambda cold starts under concurrent investigation spikes. Mitigation: reserved concurrency of 10 for the Investigation Engine Lambda in production, with provisioned concurrency for P1/P2 paths.

---

#### Decision 6: API Gateway vs. Lambda Function URL for Approval Endpoint

**Choice:** Amazon API Gateway (HTTP API) for the approval endpoint.

**Rationale:** The approval endpoint issues pre-signed URLs that embed a one-time token. API Gateway provides request throttling (prevents token enumeration attacks), WAF integration, custom domain names, usage plans, and CloudWatch access logging out of the box. The HTTP API type costs $1/million requests and adds ~2ms latency — acceptable for a human-in-the-loop action that occurs at most a few times per incident.

**Alternative considered:** Lambda Function URL. Rejected because it lacks WAF integration and per-resource throttling, which are important for an approval endpoint that could be targeted by brute-force token guessing.

**Security implication:** API Gateway resource policy restricts invocation to the HTTPS scheme. WAF rule blocks requests that do not carry the `approval_token` query parameter in the correct format (UUID v4 pattern).

---

#### Decision 7: Secrets Manager vs. Parameter Store

**Choice:** AWS Secrets Manager for all secrets (Bedrock invocation keys, cross-account role ARNs with sensitive context, SNS topic ARNs). AWS Systems Manager Parameter Store (SecureString) for non-secret configuration (model IDs, threshold values, account IDs).

**Rationale:** Secrets Manager provides automatic rotation, audit trail via CloudTrail (separate from SSM), and a clear semantic distinction between secrets and configuration. The Req 16.3 requirement to retrieve secrets by ARN at cold-start maps cleanly to `secretsmanager:GetSecretValue` by ARN. Non-secret configuration values (e.g., baseline window days, correlation time windows) do not need rotation and are more cheaply stored and retrieved via SSM Parameter Store.

**Cost implication:** Secrets Manager charges $0.40/secret/month. At ~10 secrets, this is $4/month — negligible.

---

#### Decision 8: CloudWatch vs. OpenSearch for Observability

**Choice:** Amazon CloudWatch (Logs + Metrics + Dashboards + Alarms) for all observability.

**Rationale:** CloudWatch is natively integrated with all AWS services, requires zero additional infrastructure, and the platform emits structured JSON logs that CloudWatch Logs Insights queries natively. For a portfolio demonstration platform, OpenSearch adds cost (~$50–200/month for a minimal domain) and operational burden without meaningful benefit at this scale.

**Alternative considered:** Amazon OpenSearch Service with Kinesis Firehose delivery. Retained as a future upgrade path when log volume exceeds practical CloudWatch Logs Insights query performance (~100 GB/day). The structured JSON log format chosen for all Lambdas is directly compatible with OpenSearch ingestion when that migration occurs.

**Interview note:** CloudWatch Logs Insights supports JSON field extraction natively. Emitting `{"incident_id": "...", "log_level": "INFO", ...}` from every Lambda means you can query `fields incident_id | filter log_level = "ERROR"` across all functions — effectively a correlation view without a separate log aggregation platform.

---

#### Decision 9: Security Lake OCSF vs. Raw CloudTrail

**Choice:** Ingest VPC Flow Logs via Security Lake (OCSF format) for network telemetry; use raw CloudTrail S3 delivery for management events in the AI evidence bundle.

**Rationale:** Security Lake normalizes VPC Flow Logs, Route 53 resolver logs, and Lambda data events into Open Cybersecurity Schema Framework (OCSF) format, making multi-source correlation easier. However, the AI Investigation Engine needs raw CloudTrail management events (not OCSF-normalized) for precise `eventID` citation in evidence citations and MITRE mapping. Mixing sources: Security Lake for network telemetry enrichment, raw CloudTrail S3 objects for API event evidence.

**Interview note:** OCSF normalization is valuable for downstream analytics (Athena queries, third-party SIEM) but loses fidelity for fields not in the OCSF schema. CloudTrail `eventID` is the audit anchor — always preserve raw event access.


---

## Components and Interfaces

### 3.1 Component Inventory

| Component | Runtime | Account | Trigger | Outputs |
|---|---|---|---|---|
| Telemetry Ingestion Lambda (GD) | Python 3.12 | Security | EventBridge Rule | `cloudsec-events` bus / SQS DLQ |
| Telemetry Ingestion Lambda (SH) | Python 3.12 | Security | EventBridge Rule | `cloudsec-events` bus / SQS DLQ |
| Telemetry Ingestion Lambda (CT) | Python 3.12 | Security | S3 Event (new CloudTrail object) | `cloudsec-events` bus / SQS DLQ |
| Telemetry Lag Monitor Lambda | Python 3.12 | Security | CloudWatch Events (5 min schedule) | CloudWatch metric `TelemetryIngestionLag` |
| Correlation Engine Lambda | Python 3.12 | Security | `cloudsec-events` bus rule | DynamoDB (incidents, correlation-decisions) |
| Behavior Baseline Lambda | Python 3.12 | Security | CloudWatch Events (daily schedule) | DynamoDB (baselines); `cloudsec-events` AnomalySignal |
| Incident Lifecycle SFN | Step Functions Standard | Security | Correlation Engine (StartExecution) | All downstream engines |
| AI Investigation Lambda | Python 3.12 | Security | Step Functions task | S3 (Investigation Report); DynamoDB |
| Blast Radius Lambda | Python 3.12 | Security | Step Functions task | DynamoDB (incident blast_radius field) |
| Safety Validation Lambda | Python 3.12 | Security | Step Functions task | DynamoDB (remediation-decisions); SFN token |
| Approval Lambda | Python 3.12 | Security | API Gateway POST | DynamoDB; SFN SendTaskSuccess/Failure |
| Approval Notifier Lambda | Python 3.12 | Security | Step Functions task | SNS |
| Remediation Playbook SFN (×6) | Step Functions Standard | Security | Safety Validation (StartExecution) | Cross-account Lambda; DynamoDB; S3 |
| Verification Lambda | Python 3.12 | Security | Step Functions task | DynamoDB; CloudWatch metric |
| Reporting Engine Lambda | Python 3.12 | Security | Step Functions task | S3 (JSON + Markdown reports); DynamoDB |
| Knowledge Base Ingestion Lambda | Python 3.12 | Security | EventBridge rule (RESOLVED events) | DynamoDB (knowledge-base) |
| Account Inventory Lambda | Python 3.12 | Security | CloudWatch Events (24 hr schedule) | DynamoDB (account-inventory) |
| Cross-account Read Lambda | Python 3.12 | Security | Investigation Engine | Assumes CloudSecAI-ReadRole in workload accounts |
| Cross-account Remediation Lambda | Python 3.12 | Security | Remediation Playbook SFN | Assumes CloudSecAI-RemediationRole in workload accounts |

### 3.2 End-to-End Event Flow

```
1. GuardDuty emits Finding → EventBridge default bus (us-east-1 and all regions)
2. Org-level EventBridge rule forwards to Security Account custom bus (cloudsec-events)
3. GD Ingestion Lambda receives event, normalizes to Platform schema, tags with
   source_account_id + source_region + platform_received_at
4. Normalized Finding written to cloudsec-findings DynamoDB table
5. Normalized Finding event published to cloudsec-events bus (platform.finding.created)
6. Correlation Engine Lambda triggered by platform.finding.created rule
7. Correlation Engine queries cloudsec-open-incidents-index for matching open incidents
8. If match found: adds Finding to existing Incident (DynamoDB update)
   If no match: creates new Incident (DynamoDB put), launches Incident Lifecycle SFN
9. Incident Lifecycle SFN enters INVESTIGATING state
10. SFN invokes AI Investigation Lambda (evidence assembly + Bedrock)
11. AI Investigation Lambda assembles evidence bundle from:
    - CloudTrail S3 objects (via Cross-account Read Lambda assuming CloudSecAI-ReadRole)
    - Findings from cloudsec-findings
    - AnomalySignals from cloudsec-events bus archive
    - Behavior Baseline from cloudsec-behavior-baselines
    - Config snapshots (via Config Aggregator API)
12. AI Investigation Lambda queries cloudsec-knowledge-base for similar past incidents
13. AI Investigation Lambda constructs Bedrock prompt, invokes Bedrock (Claude 3.5 Sonnet)
14. Response validated against Platform Investigation Schema (jsonschema library)
15. If validation fails: retry up to 2 times with error details in prompt
16. If all retries fail: Incident → ESCALATED, raw responses → S3 forensic bucket
17. Accepted Investigation Report written to S3 forensic bucket
18. SFN transitions to Blast Radius Analysis task
19. Blast Radius Lambda calls IAM Policy Simulator (cross-account) for affected principal
20. Blast Radius analysis result added to Investigation Report in S3
21. SFN transitions to Safety Validation task
22. Safety Validation Lambda evaluates each remediation_recommendation against Approved Action Policy
23. Execution Decision (L1/L2/L3) written to cloudsec-remediation-decisions
24. Level 1: SFN launches Remediation Playbook SFN automatically
    Level 2: SFN invokes Approval Notifier Lambda (SNS + pre-signed URL), waits for token
    Level 3: SFN transitions to Reporting (no playbook execution)
25. [Level 2 only] Approver clicks URL → API Gateway → Approval Lambda
    → validates token, expiry, self-approval → DynamoDB → SFN SendTaskSuccess/Failure
26. Remediation Playbook SFN executes against workload account (cross-account Lambda)
27. Playbook completion: SFN transitions to VERIFYING state
28. Verification Lambda performs playbook-specific checks (cross-account read)
29. All checks pass → Incident → RESOLVED
    Any check fails → Incident → ESCALATED + SNS notification
30. Reporting Engine Lambda invokes Bedrock for narrative sections
31. Narrative validated for unauthorized identifier injection
32. JSON + Markdown report written to S3 forensic bucket
33. Knowledge Base Ingestion Lambda evaluates resolved incident for KB storage eligibility
34. If eligible: anonymized entry written to cloudsec-knowledge-base
```

### 3.3 End-to-End Data Flow (Cross-Account)

```
Security Account reads from Workload Account:
  Security Account Lambda
    → sts:AssumeRole → CloudSecAI-ReadRole (Workload Account)
    → cloudtrail:LookupEvents, guardduty:ListFindings, config:GetResourceConfigHistory,
       ec2:DescribeInstances, iam:GetPolicy, iam:SimulatePrincipalPolicy
    → returns data to Security Account Lambda (never stored in Workload Account)

Security Account remediates in Workload Account:
  Remediation SFN Lambda (Security Account)
    → sts:AssumeRole → CloudSecAI-RemediationRole (Workload Account)
    → scoped remediation API calls only (specific actions per playbook)
    → results returned to Security Account for DynamoDB + S3 recording
```

---

## Data Models

### 4.1 DynamoDB Table: `cloudsec-incidents`

**Partition Key:** `incident_id` (String, UUID v4)
**Sort Key:** none (single item per incident)
**Encryption:** Dedicated KMS CMK (`cloudsec-incidents-key`)
**TTL:** `ttl_epoch` (set to creation timestamp + 365 days + grace period for archival)
**Billing:** PAY_PER_REQUEST (dev); PROVISIONED with auto-scaling (prod)

```json
{
  "incident_id":            "string (UUID v4, required)",
  "severity":               "string (P1|P2|P3|P4, required)",
  "status":                 "string (OPEN|INVESTIGATING|REMEDIATING|VERIFYING|RESOLVED|ESCALATED|REJECTED, required)",
  "creation_timestamp":     "string (ISO 8601 UTC, required)",
  "resolution_timestamp":   "string (ISO 8601 UTC, nullable)",
  "time_to_resolve_seconds":"number (nullable)",
  "source_account_id":      "string (AWS account ID, required)",
  "finding_ids":            "list<string> (required, min 1)",
  "investigation_report_s3_key": "string (nullable)",
  "blast_radius_summary":   "map (nullable, populated after Blast Radius phase)",
  "remediation_decisions":  "list<map> (nullable, populated after Safety Validation)",
  "playbook_execution_arn": "string (Step Functions execution ARN, nullable)",
  "playbook_status":        "string (SUCCEEDED|FAILED|TIMED_OUT, nullable)",
  "verification_timestamp": "string (ISO 8601 UTC, nullable)",
  "failed_verification_check": "string (nullable)",
  "remaining_active_findings": "boolean (nullable)",
  "report_s3_key_json":     "string (nullable)",
  "report_s3_key_markdown": "string (nullable)",
  "report_status":          "string (COMPLETED|STORAGE_FAILED, nullable)",
  "approval_decision":      "string (APPROVED|REJECTED, nullable)",
  "approver_arn":           "string (nullable)",
  "approval_timestamp":     "string (ISO 8601 UTC, nullable)",
  "approval_comment":       "string (max 1000 chars, nullable)",
  "quarantine_policy_arn":  "string (Playbook 1 only, nullable)",
  "forensic_artifacts":     "list<map {s3_key, etag, artifact_type, written_at}> (required)",
  "status_history":         "list<map {from, to, timestamp, reason}> (required)",
  "lifecycle_sfn_execution_arn": "string (required)",
  "ttl_epoch":              "number (Unix epoch, required)",
  "project_tag":            "string (cloudsec-ai)",
  "environment_tag":        "string (dev|staging|prod)",
  "partial_evidence_flag":  "boolean (nullable)",
  "low_baseline_confidence_flag": "boolean (nullable)"
}
```

**GSI: `status-creation-index`**
- Partition Key: `status`
- Sort Key: `creation_timestamp`
- Purpose: Query all open incidents (Correlation Engine), count by status (Observability)

**DynamoDB Streams:** Enabled (NEW_AND_OLD_IMAGES) — triggers Correlation Engine Lambda on new Finding additions to open incidents.

---

### 4.2 DynamoDB Table: `cloudsec-findings`

**Partition Key:** `finding_id` (String)
**Sort Key:** `source` (String — `GUARDDUTY|SECURITYHUB|CUSTOM`)
**Encryption:** Dedicated KMS CMK (`cloudsec-findings-key`)
**TTL:** `ttl_epoch` (90 days)

```json
{
  "finding_id":          "string (required)",
  "source":              "string (GUARDDUTY|SECURITYHUB|CUSTOM, required)",
  "severity":            "string (CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL, required)",
  "source_account_id":   "string (required)",
  "source_region":       "string (required)",
  "platform_received_at":"string (ISO 8601 UTC, required)",
  "event_timestamp":     "string (ISO 8601 UTC, required)",
  "principal_arn":       "string (nullable)",
  "source_ip":           "string (nullable)",
  "resource_arn":        "string (nullable)",
  "raw_payload":         "map (complete original JSON payload, required)",
  "incident_id":         "string (UUID v4, populated by Correlation Engine, nullable)",
  "parse_status":        "string (PARSED|FAILED, required)",
  "ttl_epoch":           "number (required)"
}
```

---

### 4.3 DynamoDB Table: `cloudsec-open-incidents-index`

This table is the Correlation Engine's hot lookup table. It stores lightweight records for all currently open incidents, indexed by the three correlation dimensions.

**Partition Key:** `index_key` (String — e.g., `principal#arn:aws:iam::123456789012:user/alice`)
**Sort Key:** `incident_id` (String)
**TTL:** 7 days (auto-cleaned when incident closes)

```json
{
  "index_key":           "string (type#value — type is PRINCIPAL|IP|RESOURCE)",
  "incident_id":         "string",
  "latest_finding_timestamp": "string (ISO 8601 UTC)",
  "incident_creation_timestamp": "string (ISO 8601 UTC)",
  "ttl_epoch":           "number"
}
```

---

### 4.4 DynamoDB Table: `cloudsec-correlation-decisions`

**Partition Key:** `finding_id` (String)
**Sort Key:** `decision_timestamp` (String, ISO 8601)
**TTL:** 90 days

```json
{
  "finding_id":          "string (required)",
  "decision_timestamp":  "string (ISO 8601 UTC, required)",
  "incident_id":         "string (required)",
  "matched_rules":       "list<string> (e.g. [PRINCIPAL_MATCH, IP_MATCH], required)",
  "eventbridge_receipt_timestamp": "string (ISO 8601 UTC, required)",
  "action":              "string (ADDED_TO_EXISTING|CREATED_NEW, required)"
}
```

---

### 4.5 DynamoDB Table: `cloudsec-behavior-baselines`

**Partition Key:** `principal_arn` (String)
**Sort Key:** none
**TTL:** `ttl_epoch` (90 days from last update)
**Encryption:** Dedicated CMK

```json
{
  "principal_arn":             "string (required)",
  "regions_used":              "set<string>",
  "api_count_by_hour":         "map<string, map> (hour_of_day_utc → {mean, stddev, sample_count})",
  "service_namespaces":        "set<string>",
  "roles_assumed":             "set<string>",
  "top20_api_actions":         "set<string>",
  "qualifying_days":           "number",
  "last_updated":              "string (ISO 8601 UTC)",
  "low_confidence":            "boolean (qualifying_days < 7)",
  "ttl_epoch":                 "number"
}
```

---

### 4.6 DynamoDB Table: `cloudsec-remediation-decisions`

**Partition Key:** `incident_id` (String)
**Sort Key:** `recommendation_hash` (String, SHA-256 of recommendation JSON)
**TTL:** 365 days

```json
{
  "incident_id":              "string",
  "recommendation_hash":      "string (SHA-256)",
  "decision_level":           "number (1|2|3)",
  "decision_timestamp":       "string (ISO 8601 UTC)",
  "action_type":              "string",
  "target_resource_arn":      "string",
  "confidence_score":         "number [0.0, 1.0]",
  "approved_action_policy_rule": "string (rule name that determined the level)",
  "rejection_reason":         "string (nullable, for input validation failures)"
}
```

---

### 4.7 DynamoDB Table: `cloudsec-approval-tokens`

**Partition Key:** `token_id` (String, UUID v4)
**TTL:** `expiry_epoch` (4 hours from creation)

```json
{
  "token_id":     "string (UUID v4)",
  "incident_id":  "string",
  "recommendation_hash": "string",
  "creator_arn":  "string (IAM principal ARN of incident creator — for self-approval prevention)",
  "expiry_epoch": "number (Unix epoch, creation + 14400 seconds)",
  "decision":     "string (PENDING|APPROVED|REJECTED, default PENDING)",
  "ttl_epoch":    "number (same as expiry_epoch)"
}
```

---

### 4.8 DynamoDB Table: `cloudsec-knowledge-base`

**Partition Key:** `attack_classification` (String)
**Sort Key:** `resolved_timestamp` (String, ISO 8601)
**TTL:** none (permanent retention for knowledge value)

```json
{
  "attack_classification":    "string (e.g. CREDENTIAL_COMPROMISE, DATA_EXFILTRATION)",
  "resolved_timestamp":       "string (ISO 8601 UTC)",
  "incident_id":              "string (anonymized — account IDs and ARNs replaced with tokens)",
  "severity":                 "string (P1|P2|P3|P4)",
  "mitre_attack_mapping":     "list<map> (anonymized)",
  "affected_resource_types":  "list<string> (resource type only, no ARNs)",
  "root_cause_summary":       "string (max 500 chars, anonymized)",
  "remediation_playbook_used":"string",
  "time_to_resolve_seconds":  "number",
  "confidence_score":         "number [0.0, 1.0]",
  "stored_at":                "string (ISO 8601 UTC)"
}
```

---

### 4.9 DynamoDB Table: `cloudsec-account-inventory`

**Partition Key:** `account_id` (String)
**Sort Key:** none

```json
{
  "account_id":   "string (AWS 12-digit account ID)",
  "account_type": "string (security|production|development|workload)",
  "account_name": "string",
  "last_updated": "string (ISO 8601 UTC)",
  "status":       "string (ACTIVE|INACTIVE)"
}
```


---

## 5. EventBridge Event Schemas

All internal platform events are published to the `cloudsec-events` custom EventBridge bus. The `source` field is always `com.cloudsec-ai` for platform-generated events. AWS-originated events forwarded from Workload Accounts retain their native `source` (e.g., `aws.guardduty`).

### 5.1 `platform.finding.created`

Published by: Telemetry Ingestion Lambda (after normalization and DynamoDB write)

```json
{
  "source": "com.cloudsec-ai",
  "detail-type": "platform.finding.created",
  "detail": {
    "finding_id":           "string (required)",
    "source":               "string (GUARDDUTY|SECURITYHUB|CUSTOM)",
    "severity":             "string (CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL)",
    "source_account_id":    "string",
    "source_region":        "string",
    "platform_received_at": "string (ISO 8601 UTC)",
    "event_timestamp":      "string (ISO 8601 UTC)",
    "principal_arn":        "string or null",
    "source_ip":            "string or null",
    "resource_arn":         "string or null"
  }
}
```

### 5.2 `platform.incident.created`

Published by: Correlation Engine Lambda

```json
{
  "source": "com.cloudsec-ai",
  "detail-type": "platform.incident.created",
  "detail": {
    "incident_id":       "string (UUID v4)",
    "severity":          "string (P1|P2|P3|P4)",
    "source_account_id": "string",
    "finding_ids":       ["string"],
    "creation_timestamp":"string (ISO 8601 UTC)"
  }
}
```

### 5.3 `platform.incident.status_changed`

Published by: Incident Lifecycle SFN (via Lambda step)

```json
{
  "source": "com.cloudsec-ai",
  "detail-type": "platform.incident.status_changed",
  "detail": {
    "incident_id":   "string",
    "from_status":   "string",
    "to_status":     "string",
    "timestamp":     "string (ISO 8601 UTC)",
    "reason":        "string or null"
  }
}
```

### 5.4 `platform.anomaly.detected` (AnomalySignal)

Published by: Behavior Baseline Lambda

```json
{
  "source": "com.cloudsec-ai",
  "detail-type": "platform.anomaly.detected",
  "detail": {
    "anomaly_type":             "string (NEW_REGION|VOLUME_SPIKE|NEW_ROLE_ASSUMPTION|NEW_SENSITIVE_API)",
    "principal_arn":            "string",
    "triggering_value":         "string (region name, assumed role ARN, or API action)",
    "observed_count":           "number or null (for VOLUME_SPIKE only)",
    "low_baseline_confidence":  "boolean",
    "timestamp":                "string (ISO 8601 UTC)",
    "source_account_id":        "string"
  }
}
```

### 5.5 `platform.telemetry.lag` (emitted as CloudWatch metric, not EventBridge event)

The Telemetry Lag Monitor Lambda queries CloudWatch for the last event receipt time per source, and emits a custom metric `TelemetryIngestionLag` with dimension `SourceName` if the gap exceeds 15 minutes. This is a scheduled Lambda, not an EventBridge rule-triggered event.

### 5.6 EventBridge Archive Configuration

The `cloudsec-events` custom bus is configured with an EventBridge Archive with:
- Archive name: `cloudsec-events-archive`
- Pattern: all events (`{}`)
- Retention: 90 days (dev: 7 days)

This enables replay of events into the Investigation Engine for re-investigation without requiring re-ingestion from source services.

### 5.7 Dead Letter Queue (SQS)

Each EventBridge rule that targets a Lambda has an SQS DLQ configured:
- Queue: `cloudsec-parse-failures-dlq`
- Retention: 14 days (as required by Req 1.7)
- Visibility timeout: 300 seconds
- KMS encryption: enabled
- CloudWatch alarm on `ApproximateNumberOfMessagesVisible > 0`

The Telemetry Ingestion Lambdas also have their own SQS DLQ for Lambda async invocation failures (`cloudsec-ingestion-async-dlq`).

---

## 6. Cross-Account IAM Architecture

### 6.1 `CloudSecAI-ReadRole` (deployed in each Workload Account)

**Trust Policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::{SECURITY_ACCOUNT_ID}:root"
    },
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": {
        "sts:ExternalId": "${var.cross_account_external_id}"
      }
    }
  }]
}
```

**Note:** In production, the Principal should be scoped to the specific Lambda execution role ARN (`arn:aws:iam::{SECURITY_ACCOUNT_ID}:role/cloudsec-investigation-lambda-role`) rather than the root. The root trust with ExternalId is the MVP default; it is acceptable for demonstration and can be tightened without code changes.

**Permission Policy (read-only, no wildcards):**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudtrail:LookupEvents",
        "cloudtrail:GetTrail",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:ListTrails"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "guardduty:ListFindings",
        "guardduty:GetFindings",
        "guardduty:ListDetectors"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "securityhub:GetFindings",
        "securityhub:BatchGetFindings"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "config:GetResourceConfigHistory",
        "config:BatchGetResourceConfig",
        "config:ListDiscoveredResources"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeNetworkInterfaces"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:ListAttachedUserPolicies",
        "iam:ListAttachedRolePolicies",
        "iam:ListUserPolicies",
        "iam:GetUserPolicy",
        "iam:GetRolePolicy",
        "iam:ListRolePolicies",
        "iam:SimulatePrincipalPolicy"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketPolicy",
        "s3:GetBucketAcl",
        "s3:ListAllMyBuckets"
      ],
      "Resource": "*"
    }
  ]
}
```

### 6.2 `CloudSecAI-RemediationRole` (deployed in each Workload Account)

**Trust Policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::{SECURITY_ACCOUNT_ID}:role/cloudsec-remediation-sfn-execution-role"
    },
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": {
        "sts:ExternalId": "${var.remediation_external_id}"
      }
    }
  }]
}
```

**Permission Policy (scoped to remediation actions only):**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Playbook1CompromisedCredential",
      "Effect": "Allow",
      "Action": [
        "iam:PutUserPolicy",
        "iam:DeleteVirtualMFADevice",
        "iam:DeactivateMFADevice",
        "iam:ListMFADevices"
      ],
      "Resource": "*"
    },
    {
      "Sid": "Playbook2SecurityGroup",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeSecurityGroups",
        "ec2:RevokeSecurityGroupIngress"
      ],
      "Resource": "*"
    },
    {
      "Sid": "Playbook3S3PublicExposure",
      "Effect": "Allow",
      "Action": [
        "s3:PutPublicAccessBlock",
        "s3:GetPublicAccessBlock",
        "s3:GetBucketPublicAccessBlock"
      ],
      "Resource": "*"
    },
    {
      "Sid": "Playbook4CompromisedEC2",
      "Effect": "Allow",
      "Action": [
        "ec2:ModifyInstanceAttribute",
        "ec2:CreateTags",
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups"
      ],
      "Resource": "*"
    },
    {
      "Sid": "Playbook5CloudTrailTampering",
      "Effect": "Allow",
      "Action": [
        "cloudtrail:StartLogging",
        "cloudtrail:GetTrail",
        "cloudtrail:GetTrailStatus",
        "s3:GetBucketPolicy",
        "s3:PutBucketPolicy"
      ],
      "Resource": "*"
    },
    {
      "Sid": "Playbook6PrivilegeEscalation",
      "Effect": "Allow",
      "Action": [
        "iam:DetachUserPolicy",
        "iam:DetachRolePolicy",
        "iam:DeleteUserPolicy",
        "iam:DeleteRolePolicy",
        "iam:GetUserPolicy",
        "iam:GetRolePolicy",
        "iam:ListAttachedUserPolicies",
        "iam:ListAttachedRolePolicies"
      ],
      "Resource": "*"
    }
  ]
}
```

**Security note:** The `Resource: "*"` in the remediation role is intentional for MVP flexibility, but Terraform variable `var.remediation_scope_arns` can restrict the resource ARN to specific resources per account in production hardening.

### 6.3 Bedrock IAM Constraint

Per Req 16.6: the Bedrock service principal (`bedrock.amazonaws.com`) must NOT appear in any role trust policy. This means Bedrock cannot assume roles — it is invoked only by Lambda functions that carry `bedrock:InvokeModel` in their execution role policies. Bedrock has no ability to call other AWS APIs on behalf of the platform.

```
CORRECT:
  cloudsec-investigation-lambda-role →
    bedrock:InvokeModel (arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-5-sonnet*)

INCORRECT (never do this):
  Trust policy: { "Principal": { "Service": "bedrock.amazonaws.com" } }
```

---

## 7. Least-Privilege IAM Model

Each Lambda function and Step Functions state machine has its own execution role. The following table summarizes the scope.

| Role Name | Principal | Key Permissions | Scope |
|---|---|---|---|
| `cloudsec-gd-ingestion-lambda-role` | Lambda | `events:PutEvents` (cloudsec-events bus), `dynamodb:PutItem` (cloudsec-findings), `sqs:SendMessage` (DLQ), `kms:GenerateDataKey` (findings key) | Narrow |
| `cloudsec-sh-ingestion-lambda-role` | Lambda | Same as GD | Narrow |
| `cloudsec-ct-ingestion-lambda-role` | Lambda | `s3:GetObject` (CloudTrail S3 bucket), `events:PutEvents`, `dynamodb:PutItem`, `sqs:SendMessage` | Narrow |
| `cloudsec-correlation-lambda-role` | Lambda | `dynamodb:GetItem`, `dynamodb:PutItem`, `dynamodb:UpdateItem`, `dynamodb:Query` (cloudsec-incidents, cloudsec-open-incidents-index, cloudsec-correlation-decisions), `sfn:StartExecution` (Incident Lifecycle SFN) | Narrow |
| `cloudsec-lifecycle-sfn-role` | Step Functions | `lambda:InvokeFunction` (specific ARNs only), `states:StartExecution` (remediation SFN ARNs only) | Narrow |
| `cloudsec-investigation-lambda-role` | Lambda | `bedrock:InvokeModel` (specific model ARN), `s3:PutObject` (forensic bucket), `dynamodb:GetItem` (findings, baselines, knowledge-base), `secretsmanager:GetSecretValue` (by ARN), `sts:AssumeRole` (CloudSecAI-ReadRole ARN) | Medium |
| `cloudsec-blast-radius-lambda-role` | Lambda | `sts:AssumeRole` (CloudSecAI-ReadRole), `dynamodb:UpdateItem` (incidents) | Narrow |
| `cloudsec-safety-validation-lambda-role` | Lambda | `dynamodb:PutItem` (remediation-decisions), `dynamodb:GetItem` (remediation-decisions), `cloudwatch:PutMetricData` | Narrow |
| `cloudsec-approval-lambda-role` | Lambda | `dynamodb:GetItem` + `UpdateItem` (approval-tokens, incidents), `sfn:SendTaskSuccess` + `sfn:SendTaskFailure` | Narrow |
| `cloudsec-remediation-sfn-role` | Step Functions | `lambda:InvokeFunction` (playbook Lambda ARNs only), `states:StartExecution` | Narrow |
| `cloudsec-remediation-lambda-role` | Lambda | `sts:AssumeRole` (CloudSecAI-RemediationRole), `s3:PutObject` (forensic bucket), `dynamodb:UpdateItem` (incidents) | Medium |
| `cloudsec-verification-lambda-role` | Lambda | `sts:AssumeRole` (CloudSecAI-ReadRole), `dynamodb:UpdateItem` (incidents), `cloudwatch:PutMetricData`, `s3:PutObject` (forensic bucket) | Medium |
| `cloudsec-reporting-lambda-role` | Lambda | `bedrock:InvokeModel`, `s3:PutObject` (forensic bucket), `dynamodb:UpdateItem` (incidents), `dynamodb:GetItem` (incidents) | Medium |
| `cloudsec-knowledge-base-lambda-role` | Lambda | `dynamodb:GetItem` (incidents), `dynamodb:PutItem` (knowledge-base), `logs:CreateLogStream` + `PutLogEvents` | Narrow |

**No role contains any `*` action.** All role policies are defined inline in Terraform with explicit `Action` lists.

---

## 8. KMS and Encryption Architecture

### 8.1 KMS CMK Inventory

Each sensitive data store has its own Customer Managed Key. Key rotation is enabled on all CMKs (annual rotation by default, which is sufficient for AES-256 envelope encryption).

| CMK Alias | Encrypts | Key Policy Principals |
|---|---|---|
| `alias/cloudsec-incidents-key` | `cloudsec-incidents` DynamoDB table | Correlation Lambda role, Lifecycle SFN role, Investigation Lambda role, Safety Validation Lambda role, Approval Lambda role, Verification Lambda role, Reporting Lambda role |
| `alias/cloudsec-findings-key` | `cloudsec-findings` DynamoDB table | All Ingestion Lambda roles, Correlation Lambda role, Investigation Lambda role |
| `alias/cloudsec-open-incidents-key` | `cloudsec-open-incidents-index` DynamoDB table | Correlation Lambda role |
| `alias/cloudsec-correlation-decisions-key` | `cloudsec-correlation-decisions` DynamoDB table | Correlation Lambda role |
| `alias/cloudsec-baselines-key` | `cloudsec-behavior-baselines` DynamoDB table | Behavior Baseline Lambda role, Investigation Lambda role |
| `alias/cloudsec-remediation-decisions-key` | `cloudsec-remediation-decisions` DynamoDB table | Safety Validation Lambda role |
| `alias/cloudsec-approval-tokens-key` | `cloudsec-approval-tokens` DynamoDB table | Approval Lambda role |
| `alias/cloudsec-knowledge-base-key` | `cloudsec-knowledge-base` DynamoDB table | Knowledge Base Lambda role, Investigation Lambda role |
| `alias/cloudsec-account-inventory-key` | `cloudsec-account-inventory` DynamoDB table | Account Inventory Lambda role |
| `alias/cloudsec-forensic-s3-key` | S3 forensic bucket | Remediation Lambda role, Verification Lambda role, Investigation Lambda role, Reporting Lambda role, Forensic write roles |
| `alias/cloudsec-dlq-key` | SQS DLQ queues | Ingestion Lambda roles |

### 8.2 S3 Bucket Encryption

The forensic S3 bucket uses SSE-KMS with `alias/cloudsec-forensic-s3-key`. The bucket policy denies any `s3:PutObject` request that does not set `x-amz-server-side-encryption: aws:kms` with the correct key ARN.

```json
{
  "Sid": "DenyUnencryptedObjectUploads",
  "Effect": "Deny",
  "Principal": "*",
  "Action": "s3:PutObject",
  "Resource": "arn:aws:s3:::{forensic-bucket}/*",
  "Condition": {
    "StringNotEquals": {
      "s3:x-amz-server-side-encryption": "aws:kms"
    }
  }
}
```

### 8.3 S3 Block Public Access

All S3 buckets (forensic, CloudTrail delivery, Terraform state) have all four Block Public Access settings enabled via Terraform:
```hcl
resource "aws_s3_bucket_public_access_block" "forensic" {
  bucket                  = aws_s3_bucket.forensic.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

### 8.4 Secrets Manager

Lambda functions retrieve secrets at cold-start using `secretsmanager:GetSecretValue` by the Secrets Manager ARN stored in an environment variable. The secret value is cached in the Lambda execution environment for the duration of the warm instance lifetime.

Secrets managed:
- `cloudsec/bedrock-model-id` — Bedrock model identifier (technically not a secret, but centralizes model configuration)
- `cloudsec/cross-account-external-id` — ExternalId for cross-account role assumption
- `cloudsec/remediation-external-id` — ExternalId for remediation role
- `cloudsec/notification-topic-arn` — SNS topic ARN for notifications
- `cloudsec/approved-action-policy` — The Approved Action Policy JSON document

No environment variable in any Lambda function contains a plaintext secret value. All environment variables referencing secrets contain only the Secrets Manager ARN.

### 8.5 DynamoDB Encryption

All DynamoDB tables use `CUSTOMER_MANAGED` encryption type with the per-table CMK specified via:
```hcl
server_side_encryption {
  enabled     = true
  kms_key_arn = aws_kms_key.incidents.arn
}
```

AWS-managed keys (`AWS_OWNED_CMK` or `AWS_MANAGED_CMK`) are not used — per Req 16.9, all tables must use platform-managed CMKs.

---

## 9. AI Investigation Engine

### 9.1 Evidence Bundle Assembly

When the Incident Lifecycle SFN enters the INVESTIGATING state, it invokes the AI Investigation Lambda with the `incident_id`. The Lambda:

1. Retrieves the Incident record from `cloudsec-incidents`
2. For each `finding_id` in the incident, retrieves the full Finding from `cloudsec-findings`
3. Queries CloudTrail for management events associated with the affected principal ARNs and resource ARNs within a 90-day lookback window (via Cross-account Read Lambda assuming `CloudSecAI-ReadRole`)
4. Retrieves `AnomalySignal` events from the EventBridge Archive (via `events:ListArchives` + `events:StartReplay` targeting a temporary replay bus, or by querying CloudWatch Logs for the correlation period)
5. Retrieves the Behavior Baseline profile from `cloudsec-behavior-baselines` for each affected principal
6. Retrieves AWS Config snapshots for affected resource ARNs (via Config Aggregator API)
7. Queries `cloudsec-knowledge-base` for entries with matching `attack_classification` (up to 3 most recent)
8. Annotates each data source with availability status — if a source fails, sets `PARTIAL_EVIDENCE` flag

**Evidence bundle size management:** If the total evidence bundle exceeds 200K characters (approaching the Bedrock context limit), the Lambda applies a priority truncation strategy:
- Priority 1 (always included): all Finding JSON payloads, Behavior Baseline, Config snapshots
- Priority 2 (include up to 100 events): CloudTrail events sorted by timestamp, most recent first
- Priority 3 (include up to 3): Knowledge Base examples

If truncation occurs, the Investigation Report is annotated with `TRUNCATED_EVIDENCE: true`.

### 9.2 Prompt Construction

The Bedrock prompt is constructed using a system prompt + user message pattern:

**System Prompt (static, stored in Secrets Manager):**
```
You are a cloud security incident investigator with deep expertise in AWS services, IAM,
and attacker techniques. You analyze security evidence and produce structured forensic reports.
You MUST respond ONLY with a valid JSON object conforming to the Platform Investigation Schema.
You MUST NOT include any text before or after the JSON object.
You MUST NOT fabricate events. Every conclusion MUST cite a specific eventID or Finding ID
from the provided evidence. If you cannot cite evidence for a claim, do not include the claim.
```

**User Message (dynamic, constructed per incident):**
```
Analyze the following security incident evidence and produce an Investigation Report.

INCIDENT ID: {incident_id}
SEVERITY: {severity}

SECURITY FINDINGS:
{finding_payloads_json}

CLOUDTRAIL EVENTS (chronological):
{cloudtrail_events_json}

ANOMALY SIGNALS:
{anomaly_signals_json}

BEHAVIOR BASELINE FOR AFFECTED PRINCIPALS:
{behavior_baseline_json}

RESOURCE CONFIGURATION SNAPSHOTS:
{config_snapshots_json}

SIMILAR PAST INCIDENTS (for context only — do not copy identifiers):
{knowledge_base_examples_json}

OUTPUT SCHEMA:
{platform_investigation_schema_json}

Produce the Investigation Report JSON now:
```

**Prompt security controls:**
- The Behavior Baseline data is stripped of absolute timestamps before inclusion (only relative patterns are sent)
- No `secretsmanager:GetSecretValue` outputs, no KMS key material, no IAM role ARNs of platform infrastructure components are included in the prompt
- Raw CloudTrail events are filtered to remove the `userIdentity.sessionContext.sessionIssuer.arn` if it belongs to a platform role
- Knowledge Base examples have all account IDs and ARNs replaced with `[ACCOUNT]` and `[ARN_TOKEN_N]` tokens before inclusion in the prompt (Req 13.7)

### 9.3 Bedrock Invocation and Retry Logic

```python
MAX_ATTEMPTS = 3
TIMEOUT_SECONDS = 30

for attempt in range(MAX_ATTEMPTS):
    try:
        response = bedrock_client.invoke_model(
            modelId=model_id,
            body=json.dumps({
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 8000,
                "messages": [{"role": "user", "content": user_message}],
                "system": system_prompt
            }),
            accept="application/json",
            contentType="application/json"
        )
        report_json = json.loads(response['body'].read())['content'][0]['text']
        validate_schema(report_json)  # raises ValidationError on failure
        break  # success
    except jsonschema.ValidationError as e:
        if attempt < MAX_ATTEMPTS - 1:
            # Include validation error in next attempt's prompt
            user_message += f"\n\nPREVIOUS ATTEMPT FAILED SCHEMA VALIDATION: {str(e)}\nPlease correct and retry."
        else:
            escalate_incident(incident_id, all_raw_responses)
            emit_metric("BedrockSchemaFailure")
            return
    except TimeoutError:
        emit_metric("BedrockInvocationTimeout")
        # Retry immediately — timeout is per-attempt
```

**Latency metric:** `BedrockInvocationLatencyMs` is emitted after each invocation (including failed attempts) with dimensions `attempt_number` and `outcome` (SUCCESS|VALIDATION_FAILURE|TIMEOUT).

### 9.4 Schema Validation

The Platform Investigation Schema (Section 10) is stored as a static JSON file bundled in the Lambda deployment package. The `jsonschema` Python library validates the response. Validation checks:
- All required top-level fields are present
- `confidence_score` is a number between 0.0 and 1.0
- `attack_timeline` entries all have required sub-fields
- `mitre_attack_mapping` entries each cite at least one `eventID` or Finding ID
- Evidence citations reference only IDs present in the evidence bundle (post-validation step — not JSON Schema, but custom Python logic)

The MITRE ATT&CK citation check (Req 5.11) is a custom validation step after JSON Schema validation:
```python
def validate_mitre_citations(report, evidence_bundle):
    valid_ids = {e['eventID'] for e in evidence_bundle['cloudtrail_events']} | \
                {f['finding_id'] for f in evidence_bundle['findings']}
    for technique in report['mitre_attack_mapping']:
        for citation in technique['evidence_citations']:
            if citation not in valid_ids:
                raise ValidationError(f"MITRE technique {technique['technique_id']} cites unknown ID {citation}")
```

---

## 10. Platform Investigation Schema

The complete JSON Schema definition for the Investigation Report:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://cloudsec-ai/schemas/investigation-report/v1",
  "title": "PlatformInvestigationReport",
  "type": "object",
  "required": [
    "incident_id",
    "schema_version",
    "confidence_score",
    "partial_evidence",
    "attack_timeline",
    "initial_access_assessment",
    "privilege_escalation_indicators",
    "persistence_indicators",
    "data_access_indicators",
    "affected_principals",
    "affected_resources",
    "mitre_attack_mapping",
    "evidence_citations",
    "blast_radius_summary",
    "remediation_recommendations"
  ],
  "additionalProperties": false,
  "properties": {
    "incident_id": {
      "type": "string",
      "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
      "description": "UUID v4 of the incident this report belongs to"
    },
    "schema_version": {
      "type": "string",
      "enum": ["1.0"],
      "description": "Platform Investigation Schema version"
    },
    "confidence_score": {
      "type": "number",
      "minimum": 0.0,
      "maximum": 1.0,
      "description": "AI confidence in conclusions, [0.0, 1.0]"
    },
    "partial_evidence": {
      "type": "boolean",
      "description": "True if one or more evidence sources were unavailable"
    },
    "missing_evidence_sources": {
      "type": "array",
      "items": { "type": "string" },
      "description": "List of unavailable sources (populated when partial_evidence is true)"
    },
    "attack_timeline": {
      "type": "array",
      "items": {
        "type": "object",
        "required": [
          "timestamp",
          "description",
          "principal_arn",
          "api_call",
          "resource_arn",
          "citation_id",
          "action_type"
        ],
        "additionalProperties": false,
        "properties": {
          "timestamp": {
            "type": "string",
            "format": "date-time",
            "description": "ISO 8601 UTC timestamp of the observed event"
          },
          "description": {
            "type": "string",
            "maxLength": 500
          },
          "principal_arn": {
            "type": "string",
            "description": "AWS principal ARN that performed the action"
          },
          "api_call": {
            "type": "string",
            "description": "AWS API call name (e.g. AssumeRole, GetObject)"
          },
          "resource_arn": {
            "type": ["string", "null"],
            "description": "ARN of the affected resource, or null if not present in source event"
          },
          "citation_id": {
            "type": "string",
            "description": "CloudTrail eventID or Finding ID that supports this entry"
          },
          "action_type": {
            "type": "string",
            "enum": [
              "INITIAL_ACCESS",
              "DISCOVERY",
              "CREDENTIAL_ACCESS",
              "PRIVILEGE_ESCALATION",
              "LATERAL_MOVEMENT",
              "PERSISTENCE",
              "COLLECTION",
              "EXFILTRATION",
              "IMPACT",
              "DEFENSE_EVASION",
              "UNKNOWN"
            ]
          },
          "source_account_id": {
            "type": "string",
            "description": "Required when timeline contains entries from multiple AWS accounts"
          },
          "timeline_gap_annotation": {
            "type": ["object", "null"],
            "properties": {
              "gap_principal_arn": { "type": "string" },
              "gap_duration_minutes": { "type": "number" }
            }
          }
        }
      }
    },
    "initial_access_assessment": {
      "type": "object",
      "required": ["vector", "confidence", "supporting_citations"],
      "additionalProperties": false,
      "properties": {
        "vector": {
          "type": "string",
          "enum": [
            "COMPROMISED_CREDENTIAL",
            "PHISHING",
            "PUBLIC_EXPOSURE",
            "SUPPLY_CHAIN",
            "INSIDER_THREAT",
            "MISCONFIGURATION",
            "UNKNOWN"
          ]
        },
        "description": { "type": "string", "maxLength": 1000 },
        "confidence": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
        "supporting_citations": {
          "type": "array",
          "items": { "type": "string" },
          "minItems": 0
        }
      }
    },
    "privilege_escalation_indicators": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["description", "api_call", "citation_id", "timestamp"],
        "additionalProperties": false,
        "properties": {
          "description": { "type": "string" },
          "api_call": { "type": "string" },
          "citation_id": { "type": "string" },
          "timestamp": { "type": "string", "format": "date-time" },
          "escalation_type": {
            "type": "string",
            "enum": ["ASSUME_ROLE", "CREATE_ACCESS_KEY", "ATTACH_POLICY", "MODIFY_TRUST_POLICY", "OTHER"]
          }
        }
      }
    },
    "persistence_indicators": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["description", "mechanism", "citation_id"],
        "additionalProperties": false,
        "properties": {
          "description": { "type": "string" },
          "mechanism": {
            "type": "string",
            "enum": ["ACCESS_KEY_CREATED", "BACKDOOR_ROLE", "LAMBDA_BACKDOOR", "CRON_JOB", "IAM_USER_CREATED", "OTHER"]
          },
          "citation_id": { "type": "string" },
          "resource_arn": { "type": ["string", "null"] }
        }
      }
    },
    "data_access_indicators": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["resource_arn", "api_call", "citation_id", "timestamp"],
        "additionalProperties": false,
        "properties": {
          "resource_arn": { "type": "string" },
          "api_call": { "type": "string" },
          "citation_id": { "type": "string" },
          "timestamp": { "type": "string", "format": "date-time" },
          "data_classification": {
            "type": "string",
            "enum": ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
          },
          "exfiltration_indicator": { "type": "boolean" }
        }
      }
    },
    "affected_principals": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["principal_arn", "principal_type", "compromise_confidence"],
        "additionalProperties": false,
        "properties": {
          "principal_arn": { "type": "string" },
          "principal_type": {
            "type": "string",
            "enum": ["IAM_USER", "IAM_ROLE", "ASSUMED_ROLE", "ROOT", "SERVICE"]
          },
          "compromise_confidence": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
          "supporting_citations": { "type": "array", "items": { "type": "string" } }
        }
      },
      "minItems": 1
    },
    "affected_resources": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["resource_arn", "resource_type", "impact_assessment"],
        "additionalProperties": false,
        "properties": {
          "resource_arn": { "type": "string" },
          "resource_type": { "type": "string" },
          "impact_assessment": {
            "type": "string",
            "enum": ["ACCESSED", "MODIFIED", "EXFILTRATED", "DESTROYED", "EXPOSED", "UNKNOWN"]
          },
          "supporting_citations": { "type": "array", "items": { "type": "string" } }
        }
      }
    },
    "mitre_attack_mapping": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["technique_id", "technique_name", "tactic", "evidence_citations"],
        "additionalProperties": false,
        "properties": {
          "technique_id": {
            "type": "string",
            "pattern": "^T[0-9]{4}(\\.[0-9]{3})?$",
            "description": "MITRE ATT&CK for Cloud technique ID"
          },
          "technique_name": { "type": "string" },
          "tactic": {
            "type": "string",
            "enum": [
              "initial-access", "execution", "persistence", "privilege-escalation",
              "defense-evasion", "credential-access", "discovery", "lateral-movement",
              "collection", "exfiltration", "impact"
            ]
          },
          "description": { "type": "string", "maxLength": 500 },
          "evidence_citations": {
            "type": "array",
            "items": { "type": "string" },
            "minItems": 1,
            "description": "Each entry must be a CloudTrail eventID or Finding ID present in the evidence bundle"
          }
        }
      }
    },
    "evidence_citations": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["citation_id", "source_type", "timestamp"],
        "additionalProperties": false,
        "properties": {
          "citation_id": { "type": "string" },
          "source_type": {
            "type": "string",
            "enum": ["CLOUDTRAIL_EVENT", "GUARDDUTY_FINDING", "SECURITYHUB_FINDING", "ANOMALY_SIGNAL", "CONFIG_SNAPSHOT"]
          },
          "timestamp": { "type": "string", "format": "date-time" },
          "relevance_note": { "type": "string", "maxLength": 200 }
        }
      }
    },
    "blast_radius_summary": {
      "type": "object",
      "required": [
        "risk_score",
        "confirmed_accessed_resources",
        "reachable_not_confirmed_resources",
        "sensitive_resources",
        "assumable_roles",
        "potential_attack_paths"
      ],
      "additionalProperties": false,
      "properties": {
        "risk_score": {
          "type": "integer",
          "minimum": 0,
          "maximum": 100,
          "description": "min(100, count_sensitive*20 + count_assumable_roles*5 + count_confirmed_accessed*10)"
        },
        "analysis_method": {
          "type": "string",
          "enum": ["IAM_POLICY_SIMULATOR", "STATIC_FALLBACK"]
        },
        "confirmed_accessed_resources": {
          "type": "array",
          "items": { "type": "string" },
          "description": "Resource ARNs with data-plane CloudTrail events in 90-day window"
        },
        "reachable_not_confirmed_resources": {
          "type": "array",
          "items": { "type": "string" }
        },
        "sensitive_resources": {
          "type": "array",
          "items": {
            "type": "object",
            "required": ["resource_arn", "sensitivity_tag"],
            "properties": {
              "resource_arn": { "type": "string" },
              "sensitivity_tag": {
                "type": "string",
                "enum": ["HIGH", "CRITICAL"]
              }
            }
          }
        },
        "assumable_roles": {
          "type": "array",
          "items": { "type": "string" }
        },
        "potential_attack_paths": {
          "type": "array",
          "maxItems": 20,
          "items": {
            "type": "object",
            "required": ["path_hops"],
            "properties": {
              "path_hops": {
                "type": "array",
                "maxItems": 3,
                "minItems": 1,
                "items": {
                  "type": "object",
                  "required": ["from_principal", "via_action", "to_resource_or_role"],
                  "properties": {
                    "from_principal": { "type": "string" },
                    "via_action": { "type": "string" },
                    "to_resource_or_role": { "type": "string" }
                  }
                }
              }
            }
          }
        }
      }
    },
    "remediation_recommendations": {
      "type": "array",
      "items": {
        "type": "object",
        "required": [
          "action_type",
          "target_resource_arn",
          "parameters",
          "confidence_score",
          "justification",
          "supporting_citations"
        ],
        "additionalProperties": false,
        "properties": {
          "action_type": {
            "type": "string",
            "description": "Must match an action type in the Approved Action Policy"
          },
          "target_resource_arn": {
            "type": "string",
            "pattern": "^arn:aws[a-z0-9-]*:[a-z0-9-]+:[a-z0-9-]*:[0-9]{12}:[a-zA-Z0-9:/_.-]+$"
          },
          "parameters": {
            "type": "object",
            "description": "Action-specific parameters — structure validated by Safety Validation Engine"
          },
          "confidence_score": {
            "type": "number",
            "minimum": 0.0,
            "maximum": 1.0
          },
          "justification": {
            "type": "string",
            "maxLength": 1000
          },
          "supporting_citations": {
            "type": "array",
            "items": { "type": "string" },
            "minItems": 1
          }
        }
      }
    }
  }
}
```


---

## 11. Hallucination and Evidence-Validation Controls

CloudSec AI uses five layers of control to prevent AI hallucination from affecting the platform's remediation decisions:

### Layer 1: Schema Enforcement
Every Bedrock response is validated against the Platform Investigation Schema (Section 10) using `jsonschema`. Fields like `confidence_score` range and `attack_timeline` array structure are formally validated. A response that fails schema validation is never accepted.

### Layer 2: Evidence Citation Requirement
The Bedrock prompt explicitly instructs the model: *"You MUST NOT fabricate events. Every conclusion MUST cite a specific eventID or Finding ID from the provided evidence."* The schema enforces `evidence_citations` as `minItems: 1` for MITRE technique entries.

### Layer 3: Citation Cross-Reference Validation
After JSON Schema validation, a custom Python function cross-references every `citation_id` in the report against the actual evidence bundle:
```python
valid_ids = {e['eventID'] for e in cloudtrail_events} | {f['finding_id'] for f in findings}
for entry in report['attack_timeline']:
    assert entry['citation_id'] in valid_ids, "Uncited timeline entry"
for technique in report['mitre_attack_mapping']:
    for cid in technique['evidence_citations']:
        assert cid in valid_ids, f"MITRE technique {technique['technique_id']} cites fabricated evidence"
```
A single uncited entry causes the entire response to be rejected and counts against the retry budget (Req 5.11).

### Layer 4: Remediation Recommendation Safety Gate
Even if a hallucinated recommendation passes all prior validation, the Safety Validation Engine independently checks each `action_type` and `target_resource_arn` against the Approved Action Policy. A hallucinated action type that is not in the Policy receives Level 3 (no execution). A hallucinated resource ARN that doesn't match allowed patterns receives Level 3.

### Layer 5: Reporting Narrative Validation
When the Reporting Engine generates narrative sections, it validates that the generated text contains no IAM principal ARNs, AWS account IDs, or resource ARNs that were not present in the Investigation Report evidence bundle. Any unauthorized identifier causes that section to be replaced with `[NARRATIVE VALIDATION FAILED]`.

**Interview note:** These five layers implement defense-in-depth against the specific failure mode of an LLM producing plausible-but-false security evidence. The key insight is that the AI system's output is never trusted directly — it is always validated against ground truth (the evidence bundle) before any action is taken.

---

## 12. Attack Timeline Reconstruction

### 12.1 Design

The `attack_timeline` array in the Investigation Report is the AI's chronological reconstruction of attacker activity. The platform enforces the following invariants regardless of model output:

1. **Citation required:** Every timeline entry must have a non-null `citation_id` pointing to a real event in the evidence bundle. Uncited entries are removed in post-validation processing.
2. **Chronological ordering:** After validation, the platform Lambda sorts the accepted timeline entries by `timestamp` ascending. If the model returns them out of order, they are re-sorted.
3. **Multi-account annotation:** If the timeline spans multiple AWS account IDs (detected by cross-referencing `citation_id` with the evidence bundle), each entry is annotated with `source_account_id`.
4. **Timeline gap detection:** A Lambda post-processing step scans consecutive entries attributed to the same `principal_arn`. If two consecutive entries are more than 60 minutes apart, a `TIMELINE_GAP` annotation is inserted between them with the principal ARN and gap duration.

### 12.2 Timeline Post-Processing Algorithm

```python
def post_process_timeline(timeline, evidence_bundle):
    # 1. Filter to only cited entries
    valid_ids = build_valid_citation_set(evidence_bundle)
    timeline = [e for e in timeline if e['citation_id'] in valid_ids]
    
    # 2. Sort by timestamp
    timeline.sort(key=lambda x: x['timestamp'])
    
    # 3. Annotate source account IDs for multi-account
    account_map = build_citation_account_map(evidence_bundle)
    if len({account_map.get(e['citation_id'], 'unknown') for e in timeline}) > 1:
        for entry in timeline:
            entry['source_account_id'] = account_map.get(entry['citation_id'], 'unknown')
    
    # 4. Insert gap annotations
    result = []
    for i, entry in enumerate(timeline):
        result.append(entry)
        if i < len(timeline) - 1:
            next_entry = timeline[i + 1]
            if entry['principal_arn'] == next_entry['principal_arn']:
                t1 = datetime.fromisoformat(entry['timestamp'])
                t2 = datetime.fromisoformat(next_entry['timestamp'])
                gap_minutes = (t2 - t1).total_seconds() / 60
                if gap_minutes > 60:
                    result.append({
                        "type": "TIMELINE_GAP",
                        "gap_principal_arn": entry['principal_arn'],
                        "gap_duration_minutes": round(gap_minutes, 1)
                    })
    
    # 5. Handle empty evidence
    return result  # returns [] if no valid entries (Req 6.3)
```

---

## 13. Blast Radius Analysis

### 13.1 IAM Policy Simulator Integration

The Blast Radius Lambda assumes `CloudSecAI-ReadRole` in the target Workload Account and calls `iam:SimulatePrincipalPolicy` to enumerate permissions. The IAM Policy Simulator API evaluates policies as AWS would — including SCPs, permission boundaries, and inline policies — and returns `ALLOWED` or `DENIED` for each simulated action.

```python
def simulate_permissions(principal_arn, resource_arns_to_test, iam_client):
    """
    Returns dict: resource_arn → list of allowed actions
    """
    all_actions = [
        # High-value actions across services
        "s3:GetObject", "s3:PutObject", "s3:DeleteObject",
        "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem",
        "ec2:DescribeInstances", "ec2:TerminateInstances",
        "lambda:InvokeFunction", "lambda:UpdateFunctionCode",
        "sts:AssumeRole",
        "iam:CreateUser", "iam:AttachUserPolicy", "iam:CreateAccessKey",
        "kms:Decrypt", "kms:GenerateDataKey",
        "secretsmanager:GetSecretValue",
        "ssm:GetParameter", "ssm:GetParameters"
    ]
    
    response = iam_client.simulate_principal_policy(
        PolicySourceArn=principal_arn,
        ActionNames=all_actions,
        ResourceArns=resource_arns_to_test
    )
    return parse_simulation_results(response)
```

### 13.2 Static Analysis Fallback

If the IAM Policy Simulator API fails (non-2xx or timeout after 30 seconds), the Blast Radius Lambda switches to static policy analysis:
1. Calls `iam:ListAttachedUserPolicies` / `iam:ListAttachedRolePolicies` and `iam:ListUserPolicies` / `iam:ListRolePolicies` to enumerate all attached and inline policies
2. Downloads each policy via `iam:GetPolicyVersion` and `iam:GetUserPolicy` / `iam:GetRolePolicy`
3. Parses the policy JSON to extract `Allow` statements and their `Resource` patterns
4. Annotates the result with `analysis_method: "STATIC_FALLBACK"`

Static analysis cannot account for Service Control Policies (SCPs) or permission boundaries, so the results are treated as an upper bound on actual permissions.

### 13.3 Risk Score Calculation

```python
def calculate_risk_score(blast_radius: dict) -> int:
    score = (
        len(blast_radius['sensitive_resources']) * 20 +
        len(blast_radius['assumable_roles']) * 5 +
        len(blast_radius['confirmed_accessed_resources']) * 10
    )
    return min(100, score)
```

This formula is from Req 7.4. The weights reflect severity: sensitive resource access (×20) is the most significant risk signal; assumable roles (×5) represent lateral movement potential; confirmed access (×10) represents evidence of realized access.

### 13.4 Cycle Detection for Attack Paths

Attack path enumeration (up to 3 hops from compromised principal) uses a DFS with a visited set to prevent cycles:

```python
def enumerate_attack_paths(start_principal, assumable_roles, max_hops=3, max_paths=20):
    paths = []
    
    def dfs(current_principal, current_path, visited):
        if len(paths) >= max_paths:
            return
        if len(current_path) > max_hops:
            return
        for role_arn in assumable_roles.get(current_principal, []):
            if role_arn in visited:  # cycle detection
                continue
            new_path = current_path + [{"from_principal": current_principal,
                                         "via_action": "sts:AssumeRole",
                                         "to_resource_or_role": role_arn}]
            paths.append({"path_hops": new_path})
            dfs(role_arn, new_path, visited | {role_arn})
    
    dfs(start_principal, [], {start_principal})
    return paths[:max_paths]
```

---

## 14. Safety Validation Engine

### 14.1 Approved Action Policy Structure

The Approved Action Policy is a JSON document stored in AWS Secrets Manager (`cloudsec/approved-action-policy`). It defines permissible actions, their reversibility classification, and allowed resource patterns.

```json
{
  "version": "1.0",
  "actions": [
    {
      "action_type": "QUARANTINE_IAM_CREDENTIAL",
      "reversible": true,
      "disruptive": false,
      "destructive": false,
      "allowed_resource_patterns": ["arn:aws:iam::*:user/*", "arn:aws:iam::*:role/*"],
      "playbook_id": "1"
    },
    {
      "action_type": "REMOVE_SECURITY_GROUP_RULE",
      "reversible": true,
      "disruptive": true,
      "destructive": false,
      "allowed_resource_patterns": ["arn:aws:ec2:*:*:security-group/*"],
      "playbook_id": "2"
    },
    {
      "action_type": "BLOCK_S3_PUBLIC_ACCESS",
      "reversible": true,
      "disruptive": false,
      "destructive": false,
      "allowed_resource_patterns": ["arn:aws:s3:::*"],
      "playbook_id": "3"
    },
    {
      "action_type": "QUARANTINE_EC2_INSTANCE",
      "reversible": true,
      "disruptive": true,
      "destructive": false,
      "allowed_resource_patterns": ["arn:aws:ec2:*:*:instance/*"],
      "playbook_id": "4"
    },
    {
      "action_type": "RESTORE_CLOUDTRAIL_LOGGING",
      "reversible": false,
      "disruptive": false,
      "destructive": false,
      "allowed_resource_patterns": ["arn:aws:cloudtrail:*:*:trail/*"],
      "playbook_id": "5"
    },
    {
      "action_type": "REMOVE_ESCALATED_PERMISSION",
      "reversible": false,
      "disruptive": true,
      "destructive": false,
      "allowed_resource_patterns": ["arn:aws:iam::*:user/*", "arn:aws:iam::*:role/*"],
      "playbook_id": "6"
    }
  ]
}
```

### 14.2 Decision Logic (Explicit Precedence)

The Safety Validation Engine evaluates in this exact order — Level 3 conditions first, then Level 2, then Level 1. The highest-severity applicable level wins.

```
Input validation (Req 8.1):
  - action_type is non-null                              → if fails: REJECT (no decision assigned)
  - target_resource_arn is non-null, valid AWS ARN format → if fails: REJECT
  - parameters is non-null object                        → if fails: REJECT
  - confidence_score is float in [0.0, 1.0]              → if fails: REJECT

Step 1 — Evaluate LEVEL 3 conditions (any match → Level 3, stop):
  a. action_type NOT in Approved Action Policy           → Level 3
  b. target_resource_arn doesn't match allowed patterns  → Level 3
  c. action is classified as "destructive"               → Level 3
  d. incident severity is P3 or P4                       → Level 3
  e. confidence_score < 0.60                             → Level 3

Step 2 — Evaluate LEVEL 2 conditions (any match → Level 2, stop):
  a. action is classified as "disruptive"                → Level 2
  b. (severity is P1 or P2) AND (0.60 ≤ confidence < 0.85) → Level 2
  c. target resource has tag CriticalityTier: PROD        → Level 2
     (checked via cross-account describe call)

Step 3 — Evaluate LEVEL 1 conditions (ALL must be true → Level 1):
  a. action is classified as "reversible"
  b. incident severity is P1 or P2
  c. confidence_score ≥ 0.85 AND ≤ 1.0
  d. target resource does NOT have tag CriticalityTier: PROD
  e. No Level 2 or Level 3 conditions applied
```

**Interview note:** The ordering matters. A recommendation with `confidence_score=0.30` for a P1 incident and a `reversible` action would incorrectly reach Level 1 if Level 3 were not evaluated first. Always evaluate the most restrictive conditions first in a safety system.

### 14.3 Audit Logging

Every Execution Decision (including rejections) is written to `cloudsec-remediation-decisions` DynamoDB before any downstream action. If the DynamoDB write fails, the Safety Validation Engine does NOT proceed — it emits `RemediationDecisionAuditFailure` and returns a blocking error to the Step Functions orchestrator (Req 8.10). This prevents silent audit gaps.

### 14.4 Level 3 Behavior

Level 3 (recommendation only) means the recommendation is recorded in the Incident record and included in the Incident Report, but no Remediation Playbook is invoked. The Reporting Engine uses Level 3 recommendations in the "Recommended Follow-Up Actions" section of the report.

---

## 15. Step Functions Workflow Designs

### 15.1 Incident Lifecycle Orchestrator (Standard Workflow)

This is the central orchestrator. It is started by the Correlation Engine when a new Incident is created.

```
StartAt: OpenIncident

States:
  OpenIncident:
    Type: Task
    Resource: arn:aws:states:::dynamodb:updateItem
    Parameters:
      TableName: cloudsec-incidents
      Key: { incident_id: { S.$: "$.incident_id" } }
      UpdateExpression: "SET #s = :status"
      ...
    Next: WaitForMinimumCorrelationWindow

  WaitForMinimumCorrelationWindow:
    Type: Wait
    Seconds: 60  # Allow 60 seconds for late-arriving correlated findings
    Next: TransitionToInvestigating

  TransitionToInvestigating:
    Type: Task
    Resource: cloudsec-status-transition-lambda-arn
    Next: AssembleEvidenceAndInvestigate

  AssembleEvidenceAndInvestigate:
    Type: Task
    Resource: cloudsec-investigation-lambda-arn
    TimeoutSeconds: 900  # 15 minutes
    Retry:
      - ErrorEquals: ["States.TaskFailed"]
        IntervalSeconds: 30
        MaxAttempts: 1
        BackoffRate: 1.0
    Catch:
      - ErrorEquals: ["States.ALL"]
        Next: EscalateIncident
    Next: BlastRadiusAnalysis

  BlastRadiusAnalysis:
    Type: Task
    Resource: cloudsec-blast-radius-lambda-arn
    TimeoutSeconds: 60
    Catch:
      - ErrorEquals: ["States.ALL"]
        Next: SafetyValidation  # Blast radius failure is non-blocking
    Next: SafetyValidation

  SafetyValidation:
    Type: Task
    Resource: cloudsec-safety-validation-lambda-arn
    Next: EvaluateDecisions

  EvaluateDecisions:
    Type: Choice
    Choices:
      - Variable: "$.decision_level"
        NumericEquals: 1
        Next: ExecuteLevel1Remediation
      - Variable: "$.decision_level"
        NumericEquals: 2
        Next: RequestHumanApproval
    Default: SkipToVerification  # Level 3 — no execution

  ExecuteLevel1Remediation:
    Type: Task
    Resource: arn:aws:states:::states:startExecution.sync
    Parameters:
      StateMachineArn.$: "$.playbook_sfn_arn"
      Input.$: "$.playbook_input"
    Next: TransitionToVerifying

  RequestHumanApproval:
    Type: Task
    Resource: arn:aws:states:::lambda:invoke.waitForTaskToken
    Parameters:
      FunctionName: cloudsec-approval-notifier-lambda-arn
      Payload:
        task_token.$: "$$.Task.Token"
        incident_id.$: "$.incident_id"
    HeartbeatSeconds: 14400  # 4 hours (Req 9.3)
    Catch:
      - ErrorEquals: ["States.HeartbeatTimeout"]
        Next: EscalateIncident  # Approval timeout → ESCALATED
    Next: EvaluateApprovalDecision

  EvaluateApprovalDecision:
    Type: Choice
    Choices:
      - Variable: "$.approval_decision"
        StringEquals: "APPROVED"
        Next: ExecuteApprovedRemediation
    Default: RecordRejection

  ExecuteApprovedRemediation:
    Type: Task
    Resource: arn:aws:states:::states:startExecution.sync
    Parameters:
      StateMachineArn.$: "$.playbook_sfn_arn"
      Input.$: "$.playbook_input"
    Next: TransitionToVerifying

  RecordRejection:
    Type: Task
    Resource: cloudsec-record-rejection-lambda-arn
    Next: SkipToVerification

  TransitionToVerifying:
    Type: Task
    Resource: cloudsec-status-transition-lambda-arn
    Parameters:
      to_status: "VERIFYING"
    Next: VerifyRemediation

  SkipToVerification:
    Type: Pass
    Result: { "skip_verification": true }
    Next: VerifyRemediation

  VerifyRemediation:
    Type: Task
    Resource: cloudsec-verification-lambda-arn
    TimeoutSeconds: 180  # 3 minutes total (start within 60s + complete within 120s)
    Next: EvaluateVerificationResult

  EvaluateVerificationResult:
    Type: Choice
    Choices:
      - Variable: "$.verification_passed"
        BooleanEquals: true
        Next: ResolveIncident
    Default: EscalateIncident

  ResolveIncident:
    Type: Task
    Resource: cloudsec-resolve-incident-lambda-arn
    Next: GenerateReport

  EscalateIncident:
    Type: Task
    Resource: cloudsec-escalate-incident-lambda-arn
    Next: GenerateReport

  GenerateReport:
    Type: Task
    Resource: cloudsec-reporting-engine-lambda-arn
    TimeoutSeconds: 180
    Next: IngestKnowledgeBase

  IngestKnowledgeBase:
    Type: Task
    Resource: cloudsec-knowledge-base-ingestion-lambda-arn
    Next: Done

  Done:
    Type: Succeed
```

---

## 16. Human Approval Workflow

### 16.1 Pre-Signed URL Architecture

When the Safety Validation Engine assigns Level 2, the Incident Lifecycle SFN pauses using `.waitForTaskToken` and invokes the Approval Notifier Lambda with the Step Functions task token.

**Approval Notifier Lambda steps:**
1. Generates a UUID v4 `token_id`
2. Writes a `cloudsec-approval-tokens` record: `{ token_id, incident_id, recommendation_hash, creator_arn, expiry_epoch: now+14400, decision: PENDING }`
3. Constructs the approval URL: `https://{api_gw_domain}/approve?token_id={token_id}&decision=APPROVED` and `REJECTED`
4. Publishes SNS message to `notification_topic_arn` with full approval context (Req 9.1)
5. Returns (does NOT call SendTaskSuccess — the SFN is still waiting)

The Step Functions task remains paused until:
- The Approval Lambda calls `sfn:SendTaskSuccess(taskToken, {approval_decision: "APPROVED"})`
- The Approval Lambda calls `sfn:SendTaskFailure(taskToken, ...)` for rejection
- The 4-hour `HeartbeatSeconds` expires → SFN catches `HeartbeatTimeout` → escalates

### 16.2 Approval Lambda Validation Chain

When the approver submits via the API Gateway endpoint:

```python
def handle_approval(token_id, decision, approver_arn, comment):
    # 1. Retrieve token record
    record = dynamodb.get_item(token_id)
    if not record:
        return error(400, "Invalid or expired token")
    
    # 2. Check expiry
    if time.time() > record['expiry_epoch']:
        return error(400, "Approval token has expired")
    
    # 3. Check self-approval (Req 9.7)
    if approver_arn == record['creator_arn']:
        return error(403, "Self-approval is not permitted")
    
    # 4. Check idempotency — already decided (Req 9.9)
    if record['decision'] != 'PENDING':
        return error(409, "Decision already recorded for this incident")
    
    # 5. Validate decision value
    if decision not in ('APPROVED', 'REJECTED'):
        return error(400, "Invalid decision value")
    
    # 6. Validate comment length
    if comment and len(comment) > 1000:
        return error(400, "Comment exceeds maximum length of 1000 characters")
    
    # 7. Record decision in DynamoDB
    dynamodb.update_item(token_id, decision=decision, approver=approver_arn, ...)
    
    # 8. Update incident record
    dynamodb.update_item(incident_id, approval_decision=decision, approver_arn=approver_arn, ...)
    
    # 9. Resume Step Functions
    if decision == 'APPROVED':
        sfn.send_task_success(task_token, output={'approval_decision': 'APPROVED'})
    else:
        sfn.send_task_failure(task_token, error='REJECTED', cause='Approver rejected remediation')
    
    return success(200, "Decision recorded")
```

### 16.3 API Gateway Configuration

- Type: HTTP API (not REST API) for lower latency and cost
- Route: `POST /approve`
- Throttle: 10 RPS burst limit (approval is a human action, burst defense)
- WAF Rule: Block requests missing `token_id` query parameter matching UUID format
- CORS: Disabled (the approval URL is submitted programmatically, not from a browser SPA)
- Authentication: None at the Gateway level — security relies on the unguessable UUID v4 token and the server-side expiry check
- Access logging: Enabled to CloudWatch Logs with 30-day retention

---

## 17. Remediation Playbook Designs

Each playbook is a Step Functions Standard Workflow named `cloudsec-remediation-{N}`. All playbooks share these properties:
- Idempotent execution (Section 18)
- Input validation as the first state
- Forensic evidence written before any resource modification
- All resource modifications performed via the Cross-account Remediation Lambda assuming `CloudSecAI-RemediationRole`
- Failure handling: transition incident to ESCALATED, log to CloudWatch Logs, do NOT modify already-written forensic evidence

### 17.1 Playbook 1: Compromised IAM Credential

```
StartAt: ValidateInput

States:
  ValidateInput:
    Type: Task
    Resource: cloudsec-playbook-input-validation-lambda
    Parameters:
      required_fields: ["target_principal_arn", "incident_id"]
      arn_format_check: ["target_principal_arn"]
    Catch: [{ErrorEquals: ["InvalidInput"], Next: FailWithValidationError}]
    Next: CheckIdempotency

  CheckIdempotency:
    # Query cloudsec-incidents to see if quarantine policy already attached
    Type: Task
    Resource: cloudsec-idempotency-check-lambda
    Next: DetermineIdempotencyBranch

  DetermineIdempotencyBranch:
    Type: Choice
    Choices:
      - Variable: "$.already_completed"
        BooleanEquals: true
        Next: RecordSuccess  # Already done — idempotent success
    Default: RecordInitialState

  RecordInitialState:
    # Write current principal state to Forensic Evidence Package BEFORE modification
    Type: Task
    Resource: cloudsec-forensic-writer-lambda
    Parameters:
      artifact_type: "PLAYBOOK_PRE_STATE"
      artifact: { principal_arn.$: "$.target_principal_arn" }
    Next: AttachQuarantinePolicy

  AttachQuarantinePolicy:
    Type: Task
    Resource: cloudsec-cross-account-remediation-lambda
    Parameters:
      action: "iam:PutUserPolicy"
      target_principal_arn.$: "$.target_principal_arn"
      policy_name.$: "States.Format('cloudsec-quarantine-{}', $.incident_id)"
      policy_document: |
        {"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}
    Retry: [{ErrorEquals:["States.TaskFailed"], MaxAttempts: 2, IntervalSeconds: 5}]
    Catch: [{ErrorEquals: ["States.ALL"], Next: FailPlaybook}]
    Next: RecordPolicyArn

  RecordPolicyArn:
    Type: Task
    Resource: cloudsec-incident-updater-lambda
    Parameters:
      field: "quarantine_policy_name"
      value.$: "States.Format('cloudsec-quarantine-{}', $.incident_id)"
    Next: CheckForMFA

  CheckForMFA:
    Type: Task
    Resource: cloudsec-cross-account-remediation-lambda
    Parameters:
      action: "iam:ListMFADevices"
      target_principal_arn.$: "$.target_principal_arn"
    Next: MFABranchDecision

  MFABranchDecision:
    Type: Choice
    Choices:
      - Variable: "$.mfa_devices_count"
        NumericGreaterThan: 0
        Next: DeactivateMFA
    Default: RecordPlaybookCompletion

  DeactivateMFA:
    Type: Task
    Resource: cloudsec-cross-account-remediation-lambda
    Parameters:
      action: "iam:DeactivateMFADevice"
      target_principal_arn.$: "$.target_principal_arn"
    Catch: [{ErrorEquals: ["States.ALL"], Next: LogMFAFailure}]
    Next: DeleteMFA

  DeleteMFA:
    Type: Task
    Resource: cloudsec-cross-account-remediation-lambda
    Parameters:
      action: "iam:DeleteVirtualMFADevice"
      target_principal_arn.$: "$.target_principal_arn"
    Catch: [{ErrorEquals: ["States.ALL"], Next: LogMFAFailure}]
    Next: RecordPlaybookCompletion

  LogMFAFailure:
    Type: Task
    Resource: cloudsec-cloudwatch-log-lambda
    Parameters:
      level: "WARN"
      message: "MFA deletion failed — principal policy quarantine still applied"
    Next: RecordPlaybookCompletion

  RecordPlaybookCompletion:
    Type: Task
    Resource: cloudsec-forensic-writer-lambda
    Parameters:
      artifact_type: "PLAYBOOK_COMPLETION"
    Next: RecordSuccess

  RecordSuccess:
    Type: Task
    Resource: cloudsec-incident-updater-lambda
    Parameters:
      playbook_status: "SUCCEEDED"
    Next: Done

  FailPlaybook:
    Type: Task
    Resource: cloudsec-playbook-failure-handler-lambda
    Next: Fail

  FailWithValidationError:
    Type: Task
    Resource: cloudsec-cloudwatch-log-lambda
    Parameters:
      level: "ERROR"
      message: "Playbook 1 terminated: invalid input parameters"
    Next: Fail

  Fail:
    Type: Fail

  Done:
    Type: Succeed
```

### 17.2 Playbook 2: Dangerous Security Group Change

Steps:
1. Input validation: `target_security_group_id`, `incident_id`
2. Idempotency check: query if offending rule already removed
3. `ec2:DescribeSecurityGroups` — retrieve current rule set
4. Write full rule set to Forensic Evidence Package
5. `ec2:RevokeSecurityGroupIngress` for rules matching port 22 or 3389 from `0.0.0.0/0` or `::/0`
6. Record completion in Incident record

### 17.3 Playbook 3: Public S3 Exposure

Steps:
1. Input validation: `target_bucket_name`, `incident_id`
2. Idempotency check: `s3:GetBucketPublicAccessBlock` — if all 4 settings already `true`, succeed
3. `s3:GetBucketPublicAccessBlock` — record current configuration to Forensic Evidence Package
4. `s3:PutPublicAccessBlock` with all 4 settings = `true`
5. Poll `s3:GetBucketPublicAccessBlock` with retry up to 30 seconds to confirm all 4 settings = `true`
6. If polling fails: transition to ESCALATED, log failure
7. Record completion

### 17.4 Playbook 4: Compromised EC2 Instance

Steps:
1. Input validation: `target_instance_id`, `incident_id`
2. Idempotency check: query instance security groups — if already only `cloudsec-quarantine`, succeed
3. `ec2:DescribeInstances` — record current security group list to Forensic Evidence Package
4. `ec2:ModifyInstanceAttribute` — replace all security groups with `cloudsec-quarantine` (no inbound/outbound rules)
5. `ec2:CreateTags` — tag instance with `SecurityStatus: QUARANTINED` and `IncidentId: {incident_id}`
6. **Explicitly NOT** terminating the instance (Req 10.4)
7. Record completion

### 17.5 Playbook 5: CloudTrail Tampering

Steps:
1. Input validation: `target_trail_arn`, `incident_id`
2. `cloudtrail:GetTrail` + `cloudtrail:GetTrailStatus` — record full trail configuration to Forensic Evidence Package
3. Idempotency check: if `IsLogging: true` AND protective S3 bucket policy already applied, succeed
4. `cloudtrail:StartLogging` — re-enable trail logging
5. Poll `cloudtrail:GetTrailStatus` for up to 60 seconds to confirm `IsLogging: true`
6. Retrieve current S3 bucket policy, record to Forensic Evidence Package
7. Apply deny policy on CloudTrail actions: deny `cloudtrail:DeleteTrail`, `cloudtrail:StopLogging`, `cloudtrail:UpdateTrail` except for ARNs in `CloudTrailProtectedPrincipals` SSM parameter
8. Record all configuration changes to Forensic Evidence Package
9. Record completion

### 17.6 Playbook 6: IAM Privilege Escalation

Steps:
1. Input validation: `target_principal_arn`, `policy_identifier`, `incident_id`
2. Retrieve full policy content (`iam:GetPolicyVersion` or `iam:GetUserPolicy` / `iam:GetRolePolicy`)
3. Write full policy content to Forensic Evidence Package **before any modification**
4. Idempotency check: if policy already detached/deleted, succeed
5. If managed policy: `iam:DetachUserPolicy` or `iam:DetachRolePolicy`
6. If inline policy: `iam:DeleteUserPolicy` or `iam:DeleteRolePolicy`
7. **Explicitly NOT** deleting the IAM principal (Req 10.6)
8. Record completion

---

## 18. Idempotency Strategy

All Remediation Playbooks implement idempotency as a first-class concern. The strategy is:

**Pattern: Check-and-Skip at Step 2 of every playbook**

Each playbook performs an idempotency check before any modification:
- Playbook 1: `cloudsec-incidents.quarantine_policy_name` is non-null AND the policy is attached → skip to success
- Playbook 2: Security group has no matching inbound rules → skip to success
- Playbook 3: `GetBucketPublicAccessBlock` returns all 4 settings = `true` → skip to success
- Playbook 4: Instance security group list contains only `cloudsec-quarantine` → skip to success
- Playbook 5: `IsLogging: true` AND protective S3 policy present → skip to success
- Playbook 6: Policy no longer attached/present for principal → skip to success

**Why this works:** The playbook's goal is a specific security state. If that state is already achieved, the playbook succeeded — regardless of which execution achieved it. The second execution does not return an error; it returns success after verifying the desired state.

**DynamoDB condition expressions:** DynamoDB writes in the idempotency path use `attribute_not_exists(incident_id)` condition expressions to prevent duplicate records from concurrent executions. If the condition fails, the write is treated as a successful duplicate.

**Step Functions execution deduplication:** The Incident Lifecycle SFN invokes playbooks with a `name` parameter set to `{incident_id}-{recommendation_hash}`. Step Functions rejects duplicate execution names (for 90 days), preventing double execution at the orchestration layer.

---

## 19. Rollback and Recovery Strategy

### 19.1 Rollback Principles

CloudSec AI does not implement automatic rollback of remediation actions. Rollback of security remediations risks re-exposing the resource that was just contained. Instead, the platform uses:

1. **Forensic evidence as rollback input:** Every playbook records the pre-modification state (security group rules, S3 bucket policy, etc.) to the Forensic Evidence Package before making changes. An operator can manually restore from this record if the remediation was incorrect.

2. **Level 3 for reversible-but-uncertain cases:** If the Safety Validation Engine's confidence threshold logic correctly classifies borderline cases as Level 3, no automatic action occurs, and the operator has the Investigation Report to make a manual decision.

3. **Playbook 1 is explicitly reversible:** The `Deny *` inline policy named `cloudsec-quarantine-{incident_id}` can be removed by detaching the inline policy. The policy naming convention makes reversal unambiguous.

### 19.2 Recovery from Infrastructure Failure

| Failure | Recovery Path |
|---|---|
| DynamoDB unavailable (Incident write) | Retry 3× with exponential backoff; emit SNS error event (Req 2.9) |
| DynamoDB unavailable (Remediation audit) | Block execution, emit `RemediationDecisionAuditFailure` (Req 8.10) |
| Bedrock all 3 attempts fail | Incident → ESCALATED; raw responses → S3 forensic bucket (Req 5.7) |
| Step Functions execution fails | SFN retries Lambda invocations; final failure → ESCALATED |
| S3 forensic write fails | Emit `ForensicWriteFailure` metric, log with incident_id, do not suppress (Req 12.10) |
| Approval timeout (4 hours) | Incident → ESCALATED via HeartbeatTimeout handler (Req 9.3) |
| Verification fails | Incident → ESCALATED with failed check recorded (Req 11.4) |
| Cross-account AssumeRole fails | Investigation proceeds with partial evidence (PARTIAL_EVIDENCE flag); blast radius uses static fallback |

---

## 20. Verification Engine

### 20.1 Design

The Verification Lambda is invoked by the Incident Lifecycle SFN after a Remediation Playbook completes. It has 60 seconds to begin execution (SFN starts the task within 60 seconds of playbook completion) and must complete all checks within 120 seconds.

### 20.2 Per-Playbook Verification Checks

**Playbook 1 (Compromised IAM Credential):**
```python
def verify_playbook_1(principal_arn, incident_id, iam_client):
    # Check 1: Deny policy attached
    inline_policies = iam_client.list_user_policies(UserName=extract_username(principal_arn))
    assert f'cloudsec-quarantine-{incident_id}' in inline_policies['PolicyNames']
    
    # Check 2: No active sessions
    # Query CloudTrail for API calls by principal in last 5 minutes
    # A perfect "no active session" check is not possible via IAM API alone;
    # the platform checks for absence of recent CloudTrail events from the principal
    # This is documented as best-effort in the Verification Report
```

**Playbook 2 (Security Group):**
```python
def verify_playbook_2(security_group_id, ec2_client):
    sg = ec2_client.describe_security_groups(GroupIds=[security_group_id])
    for rule in sg['SecurityGroups'][0]['IpPermissions']:
        assert not is_overly_permissive(rule)  # no 0.0.0.0/0 on port 22 or 3389
```

**Playbook 3 (S3 Public Access):**
```python
def verify_playbook_3(bucket_name, s3_client):
    response = s3_client.get_public_access_block(Bucket=bucket_name)
    config = response['PublicAccessBlockConfiguration']
    assert config['BlockPublicAcls'] == True
    assert config['IgnorePublicAcls'] == True
    assert config['BlockPublicPolicy'] == True
    assert config['RestrictPublicBuckets'] == True
```

**Playbook 4 (EC2 Quarantine):**
```python
def verify_playbook_4(instance_id, quarantine_sg_id, ec2_client):
    instance = ec2_client.describe_instances(InstanceIds=[instance_id])
    sgs = instance['Reservations'][0]['Instances'][0]['SecurityGroups']
    assert len(sgs) == 1
    assert sgs[0]['GroupId'] == quarantine_sg_id
```

**Playbook 5 (CloudTrail):**
```python
def verify_playbook_5(trail_arn, ct_client):
    status = ct_client.get_trail_status(Name=trail_arn)
    assert status['IsLogging'] == True
```

**Playbook 6 (Privilege Escalation):**
```python
def verify_playbook_6(principal_arn, policy_identifier, iam_client):
    # Verify the policy is no longer attached or exists as inline policy
    attached = list_all_attached_policies(principal_arn, iam_client)
    inline = list_all_inline_policy_names(principal_arn, iam_client)
    assert policy_identifier not in attached
    assert policy_identifier not in inline
```

### 20.3 Post-Verification GuardDuty/Security Hub Query

After transitioning to RESOLVED or ESCALATED, the Verification Lambda re-queries GuardDuty and Security Hub (via `CloudSecAI-ReadRole`) for any `ACTIVE` or `NEW` findings related to the affected resources. This query result is written to the Forensic Evidence Package and recorded in the Incident record as `remaining_active_findings: true/false`.

---

## 21. Forensic Evidence Architecture

### 21.1 S3 Bucket Configuration

**Bucket name:** `cloudsec-forensic-{account_id}-{region}` (globally unique)

**All objects follow the key prefix:** `{incident_id}/{artifact_type}/{timestamp_iso}/{filename}`

Example: `a1b2c3d4-e5f6-4789-abcd-123456789012/CLOUDTRAIL_EVENT/2024-01-15T10:30:00Z/event_abc123.json`

**Bucket settings (production):**
```hcl
# Object Lock — COMPLIANCE mode, 365 days
resource "aws_s3_bucket_object_lock_configuration" "forensic" {
  count  = var.environment == "prod" ? 1 : 0
  bucket = aws_s3_bucket.forensic.id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 365
    }
  }
}

# Versioning — always enabled
resource "aws_s3_bucket_versioning" "forensic" {
  bucket = aws_s3_bucket.forensic.id
  versioning_configuration { status = "Enabled" }
}

# Lifecycle — transition to Glacier after 90 days, expire after 2555 days (7 years)
resource "aws_s3_bucket_lifecycle_configuration" "forensic" {
  bucket = aws_s3_bucket.forensic.id
  rule {
    id     = "forensic-lifecycle"
    status = "Enabled"
    transition {
      days          = 90
      storage_class = "GLACIER"
    }
    expiration {
      days = 2555
    }
  }
}
```

**Bucket settings (dev/lab):**
- Object Lock: **disabled** (Object Lock cannot be enabled on an existing bucket; dev uses a separate bucket)
- Versioning: enabled
- Lifecycle: transition to Glacier after 7 days, expire after 7 days (cost optimization in dev)
- No COMPLIANCE retention — objects can be deleted by developers for test cleanup

### 21.2 Bucket Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyDeleteObject",
      "Effect": "Deny",
      "Principal": "*",
      "Action": ["s3:DeleteObject", "s3:DeleteObjectVersion", "s3:PutBucketPolicy"],
      "Resource": [
        "arn:aws:s3:::{forensic-bucket}",
        "arn:aws:s3:::{forensic-bucket}/*"
      ],
      "Condition": {
        "ArnNotEquals": {
          "aws:PrincipalArn": "${var.kms_key_admin_role_arn}"
        }
      }
    },
    {
      "Sid": "RestrictReadToInvestigatorRole",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::{forensic-bucket}/*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::{account_id}:role/cloudsec-investigator",
            "arn:aws:iam::{account_id}:role/cloudsec-*-lambda-role"
          ]
        }
      }
    },
    {
      "Sid": "DenyUnencryptedObjectUploads",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::{forensic-bucket}/*",
      "Condition": {
        "StringNotEquals": {
          "s3:x-amz-server-side-encryption": "aws:kms"
        }
      }
    },
    {
      "Sid": "EnforceSSL",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::{forensic-bucket}", "arn:aws:s3:::{forensic-bucket}/*"],
      "Condition": { "Bool": { "aws:SecureTransport": "false" } }
    }
  ]
}
```

### 21.3 Artifact Types

| Artifact Type | Written By | Content |
|---|---|---|
| `RAW_CLOUDTRAIL_EVENT` | Investigation Lambda | Individual CloudTrail event JSON |
| `FINDING_PAYLOAD` | Ingestion Lambda | Full GuardDuty/Security Hub finding JSON |
| `CONFIG_SNAPSHOT` | Investigation Lambda | AWS Config resource configuration snapshot |
| `INVESTIGATION_REPORT` | Investigation Lambda | Accepted Investigation Report JSON |
| `BEDROCK_RAW_RESPONSE` | Investigation Lambda | All Bedrock attempts (including failures) |
| `PLAYBOOK_PRE_STATE` | Remediation Lambda | Resource state before modification |
| `PLAYBOOK_COMPLETION` | Remediation Lambda | Playbook execution logs |
| `PLAYBOOK_EXECUTION_LOG` | Remediation Lambda | Step Functions execution ARN + status |
| `HUMAN_APPROVAL_RECORD` | Approval Lambda | Approver ARN, decision, timestamp, comment |
| `VERIFICATION_RESULTS` | Verification Lambda | Per-check results and API responses |
| `INCIDENT_REPORT_JSON` | Reporting Lambda | Final Incident Report (JSON) |
| `INCIDENT_REPORT_MARKDOWN` | Reporting Lambda | Final Incident Report (Markdown) |

### 21.4 ETag Recording

Whenever an artifact is written to S3, the Lambda records the `s3_key` and `ETag` (MD5 of the object content, returned by S3 `PutObject`) in the `forensic_artifacts` list in the Incident DynamoDB record within 10 seconds. This provides tamper detection — a changed ETag on the S3 object indicates modification, which is further prevented by Object Lock in production.


---

## 22. Incident Knowledge Base

### 22.1 Entry Gate (Eligibility Criteria)

An Incident is eligible for Knowledge Base storage only if:
1. Status is `RESOLVED` (not `ESCALATED`, not `REJECTED`)
2. Verification Engine recorded `REMEDIATION_CONFIRMED` signal
3. Final confidence score is ≥ 0.70 (Req 13.6)

If any criterion fails, the Knowledge Base Ingestion Lambda records the rejection reason in CloudWatch Logs and returns without writing to `cloudsec-knowledge-base`.

### 22.2 PII / Identifier Redaction

Before writing a Knowledge Base entry, all account-specific identifiers are replaced with anonymized tokens:

```python
def anonymize_for_knowledge_base(incident_data: dict) -> dict:
    """Replace AWS account IDs, ARNs, and principal names with anonymized tokens."""
    anonymized = copy.deepcopy(incident_data)
    token_map = {}  # original → token (e.g., "arn:aws:iam::123456789012:user/alice" → "[ARN_TOKEN_1]")
    token_counter = [0]
    
    def anonymize_value(v):
        if isinstance(v, str):
            # Replace 12-digit AWS account IDs
            v = re.sub(r'\b[0-9]{12}\b', '[ACCOUNT_ID]', v)
            # Replace IAM ARNs
            def replace_arn(m):
                original = m.group(0)
                if original not in token_map:
                    token_counter[0] += 1
                    token_map[original] = f'[ARN_TOKEN_{token_counter[0]}]'
                return token_map[original]
            v = re.sub(r'arn:aws[^\s"\']+', replace_arn, v)
            return v
        elif isinstance(v, dict):
            return {k: anonymize_value(val) for k, val in v.items()}
        elif isinstance(v, list):
            return [anonymize_value(item) for item in v]
        return v
    
    return anonymize_value(anonymized)
```

### 22.3 Knowledge Base Query in Investigation

During evidence assembly, the Investigation Lambda queries the Knowledge Base:
```python
response = dynamodb.query(
    TableName='cloudsec-knowledge-base',
    KeyConditionExpression='attack_classification = :ac',
    ExpressionAttributeValues={':ac': {'S': current_attack_classification}},
    ScanIndexForward=False,  # descending by resolved_timestamp
    Limit=3
)
# Include up to 3 results in Bedrock prompt
```

If 0 results, invoke Bedrock without KB examples (Req 13.5).

### 22.4 Attack Classification Taxonomy

The `attack_classification` field is a controlled vocabulary populated by the Investigation Lambda from the `initial_access_assessment.vector` and the MITRE technique patterns. The taxonomy ensures consistent partition key values for queryability:

- `CREDENTIAL_COMPROMISE` — compromised IAM credentials, access key theft
- `DATA_EXFILTRATION` — S3/DynamoDB data access patterns
- `PRIVILEGE_ESCALATION` — IAM policy manipulation
- `PERSISTENCE` — backdoor IAM users/roles, Lambda modifications
- `LATERAL_MOVEMENT` — cross-account role chaining
- `PUBLIC_EXPOSURE` — misconfigured public resources
- `CLOUDTRAIL_TAMPERING` — log deletion/disabling
- `UNKNOWN` — insufficient evidence for classification

---

## 23. Incident Reporting Architecture

### 23.1 Report Generation Flow

1. The Reporting Engine Lambda is invoked by the Incident Lifecycle SFN after RESOLVED or ESCALATED transition
2. It retrieves the full Incident record from `cloudsec-incidents`
3. It retrieves the Investigation Report from S3 (if available)
4. It assembles structured data sections (no AI needed — pure data extraction):
   - Incident ID and metadata, severity, affected identities, affected resources, blast radius, MITRE mapping table, evidence summary, automated/approved actions, verification result, remaining open risks
5. It invokes Bedrock (Claude 3.5 Sonnet) **only** for 4 narrative sections:
   - Executive summary
   - Attack timeline narrative (prose description of the `attack_timeline` array)
   - Root cause narrative
   - Recommended follow-up actions
6. Each Bedrock-generated section is validated: no unauthorized ARNs, account IDs, or principal names (Req 14.4)
7. If any section fails validation → replace with `[NARRATIVE VALIDATION FAILED]` and structured data equivalent (Req 14.5)
8. If Bedrock times out or errors → mark section as `[AI NARRATIVE UNAVAILABLE]` (Req 14.6)
9. Final JSON and Markdown reports written to S3 Forensic Evidence Package
10. S3 object keys recorded in Incident DynamoDB record
11. If S3 write fails: emit `ReportStorageFailure`, update `report_status: STORAGE_FAILED` in DynamoDB

### 23.2 Markdown Report Structure

```markdown
# CloudSec AI — Incident Report

**Incident ID:** {incident_id}
**Severity:** {severity} | **Status:** {final_status}
**Created:** {creation_timestamp} | **Resolved/Escalated:** {resolution_timestamp}
**Time to Resolve:** {time_to_resolve_seconds} seconds

## Executive Summary
{bedrock_narrative | [AI NARRATIVE UNAVAILABLE] | [NARRATIVE VALIDATION FAILED]}

## Attack Timeline
{bedrock_narrative of attack_timeline}

## Initial Access Assessment
**Vector:** {initial_access_assessment.vector}
**Confidence:** {initial_access_assessment.confidence}

## Privilege Escalation
...

## Persistence Indicators
...

## Data Access Indicators
...

## Blast Radius
**Risk Score:** {blast_radius_summary.risk_score}/100
**Analysis Method:** {analysis_method}
...

## MITRE ATT&CK Mapping
| Technique ID | Technique Name | Tactic | Evidence Citations |
...

## Automated Actions Taken
...

## Human-Approved Actions Taken
...

## Verification Result
...

## Remaining Open Risks
...

## Recommended Follow-Up Actions
{bedrock_narrative | [AI NARRATIVE UNAVAILABLE]}

---
*Report generated by CloudSec AI. AI-generated narrative sections are marked.*
```

---

## 24. Observability and Failure Handling

### 24.1 Custom CloudWatch Metrics (namespace: `CloudSecAI/Operations`)

| Metric Name | Dimensions | Published By | Description |
|---|---|---|---|
| `TelemetryIngestionLag` | `SourceName` | Lag Monitor Lambda | Seconds since last event from source; emitted when > 900s (15 min) |
| `ParseFailure` | `SourceName` | Ingestion Lambdas | Count of events routed to DLQ due to parse failure |
| `CorrelationDecision` | `ActionType` (ADDED/CREATED) | Correlation Lambda | Count of correlation decisions |
| `BedrockSchemaFailure` | (none) | Investigation Lambda | Count of incidents where all 3 Bedrock attempts failed schema validation |
| `BedrockInvocationLatencyMs` | `AttemptNumber`, `Outcome` | Investigation Lambda | Bedrock invocation duration in milliseconds |
| `RemediationDecision` | `DecisionLevel` (1\|2\|3) | Safety Validation Lambda | Count of remediation decisions by level |
| `RemediationDecisionAuditFailure` | (none) | Safety Validation Lambda | Count of DynamoDB audit write failures |
| `VerificationFailure` | `PlaybookId`, `CheckName` | Verification Lambda | Count of failed verification checks |
| `IncidentOpenCount` | `Severity` | Lag Monitor Lambda | Gauge — number of incidents in OPEN/INVESTIGATING status |
| `IncidentMTTR` | `Severity` | Lifecycle Lambda | Mean time to resolve in seconds (published on RESOLVED transition) |
| `AccountInventoryUpdateFailure` | (none) | Account Inventory Lambda | Count of failed org account list updates |
| `ForensicWriteFailure` | `ArtifactType` | Any Lambda writing to S3 | Count of failed S3 forensic writes |
| `ReportStorageFailure` | (none) | Reporting Lambda | Count of failed report S3 writes |

### 24.2 CloudWatch Alarms

| Alarm Name | Condition | Action |
|---|---|---|
| `CloudSecAI-BedrockSchemaFailures` | `BedrockSchemaFailure` > 3 in 5 min | SNS notification |
| `CloudSecAI-VerificationFailures` | `VerificationFailure` > 1 in 15 min | SNS notification |
| `CloudSecAI-TelemetryLag` | `TelemetryIngestionLag` > 900 for any SourceName | SNS notification |
| `CloudSecAI-RemediationSFNFailed` | Step Functions `ExecutionsFailed` > 0 in 1 min | SNS notification |
| `CloudSecAI-DLQNotEmpty` | `cloudsec-parse-failures-dlq` ApproximateNumberOfMessagesVisible > 0 | SNS notification |
| `CloudSecAI-ForensicWriteFailures` | `ForensicWriteFailure` > 0 in 5 min | SNS notification |
| `CloudSecAI-AuditFailures` | `RemediationDecisionAuditFailure` > 0 in 5 min | SNS notification |

### 24.3 Lambda Structured Log Format

All Lambda functions emit JSON logs conforming to this structure:
```json
{
  "timestamp": "2024-01-15T10:30:00.123Z",
  "log_level": "INFO",
  "function_name": "cloudsec-investigation-lambda",
  "request_id": "abc-123-def",
  "incident_id": "a1b2c3d4-e5f6-4789-abcd-123456789012",
  "message": "Evidence bundle assembled: 47 CloudTrail events, 3 findings",
  "duration_ms": 1250,
  "metadata": {}
}
```

**Prohibited content (Req 15.5):** No credentials, KMS key material, raw secret values, or complete CloudTrail event payloads in logs. CloudTrail events are logged by `eventID` only.

### 24.4 Log Group Configuration

- All Lambda function log groups: 30-day retention
- Log group names: `/aws/lambda/cloudsec-{function-name}`
- Log groups for Step Functions execution history: `/aws/states/cloudsec-{sfn-name}`

### 24.5 CloudWatch Dashboard

Dashboard named `CloudSecAI-Operations` with the following widgets:
1. Incident counts by status (bar chart)
2. Bedrock invocation latency p50/p95/p99 (line chart, 1-hour period)
3. Lambda error rates by function (line chart)
4. Step Functions execution success/failure rates by state machine (bar chart)
5. Telemetry ingestion lag by source (line chart)
6. Remediation decision counts by level (bar chart)
7. DLQ message count (line chart)
8. MTTR by severity (bar chart)

### 24.6 AWS Budgets Alert

Budget scoped to tag `Project: cloudsec-ai`, alerting when estimated monthly spend exceeds USD 75 (Req 15.7). Notification sent to `notification_topic_arn`.

### 24.7 Dead Letter Queues — Complete Inventory

| DLQ Name | Trigger | Retention | Alert Condition |
|---|---|---|---|
| `cloudsec-parse-failures-dlq` | EventBridge rule failure | 14 days | > 0 messages |
| `cloudsec-ingestion-async-dlq` | Lambda async invocation failure | 14 days | > 0 messages |
| `cloudsec-correlation-dlq` | Correlation Lambda failure | 14 days | > 0 messages |

All DLQs are encrypted with `alias/cloudsec-dlq-key`.

---

## 25. Behavior Baseline System

### 25.1 Baseline Update Lambda

Runs on a daily CloudWatch Events schedule. For each unique principal ARN observed in CloudTrail over the last 30 days (with ≥10 API calls on a given day for that day to qualify):

```python
def update_baseline_for_principal(principal_arn, cloudtrail_events_30d):
    qualifying_days = [
        day for day in cloudtrail_events_30d
        if count_calls_on_day(day, principal_arn) >= 10
    ]
    
    if len(qualifying_days) == 0:
        low_confidence = True
    else:
        low_confidence = len(qualifying_days) < 7
    
    baseline = {
        'principal_arn': principal_arn,
        'regions_used': extract_unique_regions(qualifying_days),
        'api_count_by_hour': compute_hourly_distribution(qualifying_days),
        'service_namespaces': extract_service_namespaces(qualifying_days),
        'roles_assumed': extract_assumed_roles(qualifying_days),
        'top20_api_actions': extract_top_n_apis(qualifying_days, n=20),
        'qualifying_days': len(qualifying_days),
        'last_updated': utcnow(),
        'low_confidence': low_confidence,
        'ttl_epoch': utcnow_epoch() + 90 * 86400
    }
    
    dynamodb.put_item('cloudsec-behavior-baselines', baseline)
```

### 25.2 Anomaly Detection

The Baseline Lambda also runs anomaly detection on incoming CloudTrail events (triggered from the `cloudsec-events` bus for newly ingested CT events):

1. **NEW_REGION:** `event.awsRegion not in baseline.regions_used`
2. **VOLUME_SPIKE:** Count of API calls in the current UTC hour exceeds `mean + 3 * stddev` for that hour-of-day, AND `sample_count ≥ 5` for that hour (Req 4.4)
3. **NEW_ROLE_ASSUMPTION:** `event.requestParameters.roleArn not in baseline.roles_assumed` (for `sts:AssumeRole` events)
4. **NEW_SENSITIVE_API:** `event.eventName` in IAM/STS/Organizations namespace and not in `baseline.top20_api_actions` (Req 4.6)

All anomaly events include `low_baseline_confidence: true` if `qualifying_days < 7` or if the principal has no baseline record yet.

---

## 26. Correlation Engine Design

### 26.1 Algorithm

The Correlation Engine is a Lambda triggered by `platform.finding.created` events on the `cloudsec-events` bus.

```python
def correlate_finding(finding: dict):
    # Build candidate queries based on available attributes
    candidate_incident_ids = set()
    matched_rules = []
    
    # Rule 1: Principal ARN match within 30 minutes (Req 3.1)
    if finding.get('principal_arn'):
        key = f'principal#{finding["principal_arn"]}'
        incidents = query_open_index(key, finding['event_timestamp'], window_minutes=30)
        for i in incidents:
            candidate_incident_ids.add(i['incident_id'])
            matched_rules.append('PRINCIPAL_MATCH')
    
    # Rule 2: Source IP match within 15 minutes (Req 3.2)
    if finding.get('source_ip'):
        key = f'ip#{finding["source_ip"]}'
        incidents = query_open_index(key, finding['event_timestamp'], window_minutes=15)
        for i in incidents:
            candidate_incident_ids.add(i['incident_id'])
            matched_rules.append('IP_MATCH')
    
    # Rule 3: Resource ARN match within 60 minutes (Req 3.3)
    if finding.get('resource_arn'):
        key = f'resource#{finding["resource_arn"]}'
        incidents = query_open_index(key, finding['event_timestamp'], window_minutes=60)
        for i in incidents:
            candidate_incident_ids.add(i['incident_id'])
            matched_rules.append('RESOURCE_MATCH')
    
    if candidate_incident_ids:
        # Multiple matches: choose oldest (Req 3.4)
        target_incident = get_oldest_incident(candidate_incident_ids)
        add_finding_to_incident(finding, target_incident, matched_rules)
        write_correlation_decision(finding, target_incident, matched_rules)
    else:
        # No match: create new incident (Req 3.5)
        new_incident = create_incident(finding)
        write_correlation_decision(finding, new_incident, [])
        start_incident_lifecycle_sfn(new_incident)
    
    # Update open incidents index for future correlation
    update_open_incidents_index(finding, target_incident_id)
```

### 26.2 Time Complexity

The `cloudsec-open-incidents-index` table supports O(1) lookups by index key (principal ARN, IP, resource ARN) + time range filtering. With thousands of concurrent open incidents, the correlation step remains fast because it queries by specific key, not by scan. Each correlation event touches at most 3 DynamoDB queries (one per rule).

### 26.3 Race Condition Handling

If two findings arrive simultaneously and both try to create new incidents for the same principal ARN, DynamoDB conditional writes prevent duplicate incident creation. The `cloudsec-incidents` table uses `attribute_not_exists(incident_id)` for new incident creation. The loser of the race condition detects the existing incident on retry and adds the finding to it instead.

---

## 27. Terraform Module Architecture

### 27.1 Directory Structure

```
terraform/
├── environments/
│   ├── dev/
│   │   ├── main.tf          # Root module instantiation
│   │   ├── backend.tf       # S3 backend + DynamoDB lock table
│   │   └── dev.tfvars       # Dev-specific variables
│   ├── staging/
│   │   ├── main.tf
│   │   ├── backend.tf
│   │   └── staging.tfvars
│   └── prod/
│       ├── main.tf
│       ├── backend.tf
│       └── prod.tfvars
├── modules/
│   ├── security-lake/
│   │   ├── main.tf          # Security Lake data lake, S3 bucket, VPC Flow Log delivery
│   │   ├── variables.tf     # vpc_ids, log_destination_arn
│   │   └── outputs.tf       # security_lake_arn
│   ├── telemetry-ingestion/
│   │   ├── main.tf          # EventBridge bus, rules, ingestion Lambdas, SQS DLQs
│   │   ├── variables.tf     # notification_topic_arn, forensic_bucket_arn, kms_key_arns
│   │   └── outputs.tf       # event_bus_arn, dlq_arns
│   ├── incident-store/
│   │   ├── main.tf          # All DynamoDB tables + KMS CMKs
│   │   ├── variables.tf     # environment, tags
│   │   └── outputs.tf       # table ARNs, CMK ARNs
│   ├── correlation-engine/
│   │   ├── main.tf          # Correlation Lambda, DynamoDB Streams trigger, EventBridge rule
│   │   ├── variables.tf     # incident_table_arn, open_incidents_table_arn, event_bus_arn
│   │   └── outputs.tf       # lambda_arn
│   ├── behavior-baseline/
│   │   ├── main.tf          # Baseline Lambda, CloudWatch Events schedule
│   │   ├── variables.tf     # baselines_table_arn, event_bus_arn, cloudtrail_bucket_arn
│   │   └── outputs.tf       # lambda_arn
│   ├── investigation-engine/
│   │   ├── main.tf          # Investigation Lambda, Bedrock IAM, schema JSON asset
│   │   ├── variables.tf     # bedrock_model_id_secret_arn, forensic_bucket_arn, kms_arns
│   │   └── outputs.tf       # lambda_arn
│   ├── blast-radius/
│   │   ├── main.tf          # Blast Radius Lambda, cross-account read role
│   │   ├── variables.tf     # read_role_arn, incidents_table_arn
│   │   └── outputs.tf       # lambda_arn
│   ├── safety-validation/
│   │   ├── main.tf          # Safety Validation Lambda, Approved Action Policy (in Secrets Manager)
│   │   ├── variables.tf     # decisions_table_arn, approved_action_policy_secret_arn
│   │   └── outputs.tf       # lambda_arn
│   ├── remediation-playbooks/
│   │   ├── main.tf          # 6 Step Functions state machines, cross-account remediation Lambda
│   │   ├── variables.tf     # remediation_role_arn, forensic_bucket_arn, incidents_table_arn
│   │   └── outputs.tf       # playbook_sfn_arns (map by playbook_id)
│   ├── approval-workflow/
│   │   ├── main.tf          # API Gateway HTTP API, Approval Lambda, SNS, approval-tokens table
│   │   ├── variables.tf     # notification_topic_arn, incidents_table_arn, tokens_table_arn
│   │   └── outputs.tf       # api_gateway_url, approval_lambda_arn
│   ├── verification-engine/
│   │   ├── main.tf          # Verification Lambda
│   │   ├── variables.tf     # read_role_arn, incidents_table_arn, forensic_bucket_arn
│   │   └── outputs.tf       # lambda_arn
│   ├── forensic-evidence/
│   │   ├── main.tf          # S3 forensic bucket, Object Lock (conditional on env), KMS CMK, lifecycle
│   │   ├── variables.tf     # environment, kms_admin_role_arn
│   │   └── outputs.tf       # forensic_bucket_arn, forensic_kms_key_arn
│   ├── knowledge-base/
│   │   ├── main.tf          # Knowledge Base DynamoDB table, KMS CMK, Ingestion Lambda
│   │   ├── variables.tf     # incidents_table_arn, event_bus_arn
│   │   └── outputs.tf       # knowledge_base_table_arn, lambda_arn
│   ├── reporting-engine/
│   │   ├── main.tf          # Reporting Lambda, Bedrock IAM, SNS publish permission
│   │   ├── variables.tf     # forensic_bucket_arn, incidents_table_arn, bedrock_model_id_secret_arn
│   │   └── outputs.tf       # lambda_arn
│   ├── observability/
│   │   ├── main.tf          # CloudWatch Alarms, Dashboard, Budgets, Log group retention
│   │   ├── variables.tf     # notification_topic_arn, environment, monthly_budget_usd
│   │   └── outputs.tf       # dashboard_name, alarm_arns
│   └── cross-account-roles/
│       ├── main.tf          # CloudSecAI-ReadRole + CloudSecAI-RemediationRole (deployed to workload accounts)
│       ├── variables.tf     # security_account_id, remediation_sfn_role_arn, external_ids
│       └── outputs.tf       # read_role_arn, remediation_role_arn
```

### 27.2 Module Boundaries and Dependency Graph

```
forensic-evidence        (no module deps)
incident-store           (no module deps)
observability            (no module deps)
security-lake            (no module deps)
cross-account-roles      (no module deps — deployed to workload accounts separately)
  │
telemetry-ingestion      (depends on: incident-store, forensic-evidence)
  │
correlation-engine       (depends on: incident-store, telemetry-ingestion)
  │
behavior-baseline        (depends on: incident-store, telemetry-ingestion)
  │
investigation-engine     (depends on: incident-store, forensic-evidence, knowledge-base)
  │
blast-radius             (depends on: incident-store)
  │
safety-validation        (depends on: incident-store)
  │
approval-workflow        (depends on: incident-store)
  │
remediation-playbooks    (depends on: incident-store, forensic-evidence)
  │
verification-engine      (depends on: incident-store, forensic-evidence)
  │
reporting-engine         (depends on: incident-store, forensic-evidence, knowledge-base)
  │
knowledge-base           (depends on: incident-store)
```

### 27.3 Terraform State Backend

```hcl
# terraform/environments/{env}/backend.tf
terraform {
  backend "s3" {
    bucket         = "cloudsec-tf-state-{account_id}-{region}"
    key            = "cloudsec-ai/{env}/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "cloudsec-tf-state-lock"
    encrypt        = true
    kms_key_id     = "alias/cloudsec-tf-state-key"
  }
}
```

The state backend bucket and lock table are deployed manually (bootstrap) before running Terraform for the first time. They are not managed by the platform's own Terraform (avoids bootstrapping paradox).

### 27.4 Key Terraform Variables (No Hard-Coded Values)

All environment-specific values are in `.tfvars` files or read from SSM. No AWS account IDs, region names, ARNs, or secret values appear in `.tf` files.

```hcl
# dev.tfvars example (no actual secret values)
environment              = "dev"
aws_region               = "us-east-1"
security_account_id      = var.security_account_id  # injected from CI/CD
workload_account_ids     = []                        # single account in dev
notification_topic_arn   = ""                        # disabled in dev
monthly_budget_usd       = 75
enable_object_lock       = false                     # dev: no Object Lock
s3_retention_days        = 7
dynamodb_ttl_days        = 7
kms_admin_role_arn       = ""                        # TBD in dev
```

---

## 28. Testing Architecture

### 28.1 Unit Tests (pytest)

All Lambda handlers have `tests/unit/` test files achieving ≥80% line coverage (Req 19.1).

**Structure:**
```
src/
  lambdas/
    ingestion/handler.py
    correlation/handler.py
    investigation/handler.py
    safety_validation/handler.py
    ...
tests/
  unit/
    test_ingestion.py
    test_correlation.py
    test_investigation.py
    test_safety_validation.py
    test_blast_radius.py
    test_approval.py
    test_verification.py
    test_reporting.py
    test_behavior_baseline.py
    test_knowledge_base.py
    conftest.py  # shared fixtures, moto setup
```

**Key test patterns:**
```python
# Safety Validation tests
def test_level3_unknown_action():
    """Actions not in Approved Action Policy always receive Level 3 (Req 8.3)."""
    result = evaluate_decision(
        action_type="UNKNOWN_ACTION",
        target_arn="arn:aws:iam::123456789012:user/test",
        confidence_score=0.95,
        severity="P1",
        policy=approved_action_policy()
    )
    assert result.level == 3

def test_level1_all_conditions_met():
    """Level 1 requires all conditions: reversible, P1/P2, confidence ≥ 0.85, non-PROD."""
    result = evaluate_decision(
        action_type="QUARANTINE_IAM_CREDENTIAL",  # reversible
        target_arn="arn:aws:iam::123456789012:user/test",
        confidence_score=0.90,
        severity="P1",
        resource_criticality_tier="MEDIUM",
        policy=approved_action_policy()
    )
    assert result.level == 1

def test_level3_takes_precedence_over_level1():
    """Level 3 conditions are evaluated first — low confidence overrides reversible+P1."""
    result = evaluate_decision(
        action_type="QUARANTINE_IAM_CREDENTIAL",  # reversible
        target_arn="arn:aws:iam::123456789012:user/test",
        confidence_score=0.50,  # below 0.60 threshold → Level 3
        severity="P1",
        resource_criticality_tier="MEDIUM",
        policy=approved_action_policy()
    )
    assert result.level == 3
```

### 28.2 Integration Tests (moto)

Integration tests cover the end-to-end flow from GuardDuty Finding ingestion through Incident creation and Correlation Engine assignment (Req 19.2).

```python
@mock_dynamodb
@mock_events
def test_end_to_end_finding_to_open_incident(dynamodb_resource, events_client):
    """
    Starting at a simulated EventBridge event (GuardDuty finding),
    ending with a DynamoDB Incident record in OPEN status.
    """
    # Setup mocked DynamoDB tables
    setup_mock_tables(dynamodb_resource)
    
    # Simulate GuardDuty finding event
    finding_event = build_guardduty_finding_event(
        principal_arn="arn:aws:iam::123456789012:user/attacker",
        severity="HIGH"
    )
    
    # Invoke ingestion Lambda
    ingestion_lambda.handler(finding_event, MockContext())
    
    # Verify Finding in DynamoDB
    finding = dynamodb_resource.Table('cloudsec-findings').get_item(
        Key={'finding_id': finding_event['detail']['id'], 'source': 'GUARDDUTY'}
    )
    assert finding['Item']['severity'] == 'HIGH'
    
    # Simulate correlation event (finding.created event)
    correlation_event = build_platform_finding_created_event(finding['Item'])
    correlation_lambda.handler(correlation_event, MockContext())
    
    # Verify Incident created in OPEN status
    incidents = scan_incidents(dynamodb_resource)
    assert len(incidents) == 1
    assert incidents[0]['status'] == 'OPEN'
    assert finding_event['detail']['id'] in incidents[0]['finding_ids']
```

### 28.3 JSON Schema Validation Tests

```python
# Test valid reports pass validation
def test_valid_report_passes_schema():
    report = build_valid_investigation_report()
    validate_against_schema(report)  # should not raise

# Test invalid reports fail validation
@pytest.mark.parametrize("missing_field", [
    "incident_id", "confidence_score", "attack_timeline",
    "mitre_attack_mapping", "blast_radius_summary", "remediation_recommendations"
])
def test_missing_required_field_fails_schema(missing_field):
    report = build_valid_investigation_report()
    del report[missing_field]
    with pytest.raises(jsonschema.ValidationError):
        validate_against_schema(report)

def test_confidence_score_out_of_range_fails():
    report = build_valid_investigation_report()
    report['confidence_score'] = 1.5  # invalid
    with pytest.raises(jsonschema.ValidationError):
        validate_against_schema(report)

def test_mitre_technique_without_citation_fails():
    report = build_valid_investigation_report()
    report['mitre_attack_mapping'][0]['evidence_citations'] = []  # minItems: 1
    with pytest.raises(jsonschema.ValidationError):
        validate_against_schema(report)
```

### 28.4 Idempotency Tests

```python
@pytest.mark.parametrize("playbook_id", [1, 2, 3, 4, 5, 6])
def test_playbook_idempotency(playbook_id, mock_sfn, mock_aws_resources):
    """
    Invoke each Remediation Playbook twice for the same Incident ID and target resource.
    Assert: target resource is in the same protection state after both invocations.
    Both invocations should complete without error.
    """
    input_data = build_playbook_input(playbook_id, incident_id="test-incident-001")
    
    # First invocation
    result1 = invoke_playbook(playbook_id, input_data, mock_sfn, mock_aws_resources)
    state_after_first = get_resource_state(playbook_id, mock_aws_resources)
    
    # Second invocation
    result2 = invoke_playbook(playbook_id, input_data, mock_sfn, mock_aws_resources)
    state_after_second = get_resource_state(playbook_id, mock_aws_resources)
    
    assert result1['status'] == 'SUCCEEDED'
    assert result2['status'] == 'SUCCEEDED'
    assert state_after_first == state_after_second
```

### 28.5 Negative Tests (Safety Validation)

```python
def test_action_not_in_policy_gets_level3():
    assert evaluate_decision("DELETE_ALL_USERS", ...).level == 3

def test_invalid_arn_gets_rejected():
    with pytest.raises(InputValidationError):
        evaluate_decision(..., target_arn="not-a-valid-arn")

def test_null_action_type_rejected():
    with pytest.raises(InputValidationError):
        evaluate_decision(..., action_type=None)

def test_confidence_below_0_60_gets_level3():
    assert evaluate_decision(..., confidence_score=0.59).level == 3

def test_prod_tagged_resource_gets_level2():
    assert evaluate_decision(..., resource_criticality_tier="PROD").level == 2
```

### 28.6 Terraform Validation Tests (CI Pipeline)

```bash
# In CI pipeline (GitHub Actions / CodeBuild):
cd terraform/modules/{module_name}
terraform init -backend=false
terraform validate

cd terraform/environments/dev
terraform init -backend=false -var-file=dev.tfvars
terraform plan -var-file=dev.tfvars -out=tfplan

# tflint
tflint --recursive
```

### 28.7 Coverage Configuration

```ini
# pytest.ini
[pytest]
testpaths = tests
addopts = --cov=src --cov-report=xml --cov-fail-under=80

[coverage:run]
source = src
omit = */test_*, */conftest.py
```

---

## 29. Safe Attack-Simulation Architecture

### 29.1 Account Guard

Every simulation script begins with a mandatory account ID check:

```python
#!/usr/bin/env python3
"""
Attack Simulation: Compromised IAM Credential
SAFE TO RUN IN LAB ACCOUNT ONLY.
"""

LAB_ACCOUNT_ID = "123456789012"  # Lab account constant — never production

def main():
    sts = boto3.client('sts')
    current_account = sts.get_caller_identity()['Account']
    
    if current_account != LAB_ACCOUNT_ID:
        print(f"ERROR: This script must only run in lab account {LAB_ACCOUNT_ID}.")
        print(f"Current account: {current_account}. Exiting.")
        sys.exit(1)
    
    print(f"Account guard passed. Running in lab account {current_account}.")
    run_simulation()
```

The Lab Account has no IAM trust relationship with the Security Account or any Production/Development accounts (Req 20.2).

### 29.2 Simulation Script Structure

```
attack-simulations/
├── README.md
├── lab_account_id.py          # LAB_ACCOUNT_ID constant (shared by all scripts)
├── sim_01_compromised_credential/
│   ├── simulate.py            # Simulation steps
│   ├── cleanup.py             # Restore pre-simulation state
│   └── expected_findings.json # Expected GuardDuty/Security Hub finding types
├── sim_02_security_group/
├── sim_03_s3_public_exposure/
├── sim_04_compromised_ec2/
├── sim_05_cloudtrail_tampering/
└── sim_06_privilege_escalation/
```

### 29.3 Simulation Report

Each simulation script produces a `simulation_report_{timestamp}.json`:
```json
{
  "simulation_id": "sim_01_compromised_credential",
  "executed_at": "2024-01-15T10:00:00Z",
  "lab_account_id": "123456789012",
  "steps_performed": [
    { "step": "Created test IAM user", "status": "COMPLETED" },
    { "step": "Generated access key", "status": "COMPLETED" },
    { "step": "Made API calls from unusual region", "status": "COMPLETED" }
  ],
  "expected_detection_signal": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
  "actual_incident_id": "a1b2c3d4-e5f6-4789-abcd-123456789012",
  "remediation_action_taken": "QUARANTINE_IAM_CREDENTIAL (Level 1)"
}
```

### 29.4 Cleanup Verification

```python
def cleanup_and_verify():
    """Restore lab environment and verify pre-simulation state."""
    # Perform cleanup actions
    cleanup_resources()
    
    # Verify restoration
    failures = []
    for check in pre_simulation_state_checks:
        result = check.verify()
        if not result.passed:
            failures.append(check.name)
    
    if failures:
        print(f"CLEANUP VERIFICATION FAILED: {failures}")
        sys.exit(1)
    
    print("Cleanup verification passed. Lab environment restored.")
    sys.exit(0)
```

---

## 30. Development vs. Production Architecture

### 30.1 Configuration Differences

| Feature | Dev/Lab | Production |
|---|---|---|
| AWS accounts | Single account (no cross-account) | Security Account + N Workload Accounts |
| S3 Object Lock | Disabled (separate bucket) | COMPLIANCE mode, 365 days |
| S3 retention | 7 days → expire | 90 days → Glacier → 7 years expire |
| DynamoDB TTL | 7 days on all tables | 365 days for incidents; per-table as designed |
| Lambda size | 512 MB for most functions | 1024–3008 MB for Investigation Engine |
| Reserved concurrency | None | 10 for Investigation Engine |
| Provisioned concurrency | None | 2 for Investigation Engine (P1/P2 path) |
| CloudWatch log retention | 7 days | 30 days |
| GuardDuty | Disabled or dev detector only | Organization-level enabled |
| Security Hub | Disabled or dev only | Organization-level enabled |
| CloudTrail | Local trail, no org trail | Organization-level multi-region trail |
| Bedrock | Same Claude 3.5 Sonnet | Same Claude 3.5 Sonnet |
| Approval timeout | 4 hours | 4 hours |
| Multi-region | Single region | Single region (can expand) |
| WAF on API Gateway | Disabled | Enabled |
| AWS Budgets alert | $75/month | $75/month (same) |
| Terraform backend | Local state (developer machine) | S3 + DynamoDB (shared team state) |
| Cross-account roles | Not deployed | Deployed to all Workload Accounts |

### 30.2 Practical Dev Defaults

Developers working locally can target the dev environment with:
```bash
cd terraform/environments/dev
terraform init
terraform plan -var-file=dev.tfvars
terraform apply -var-file=dev.tfvars
```

The dev environment stands up a complete functional platform in a single AWS account. Lambda functions that normally assume cross-account roles instead operate directly in the same account using a simplified IAM setup. Object Lock is not present, allowing `terraform destroy` to cleanly remove all resources.

**Object Lock important note:** Object Lock must be enabled at bucket creation time. The dev Terraform creates a **different** bucket (`cloudsec-forensic-dev-{account_id}`) without Object Lock. The prod Terraform creates `cloudsec-forensic-prod-{account_id}` with Object Lock. The bucket name is passed as a Terraform output to all modules — no module hard-codes the bucket name.

---

## 31. Cost Estimate

All estimates assume US East (N. Virginia). "Dev" assumes ~2 test incidents/day; "Prod" assumes ~20 incidents/day with P1/P2 workloads.

| Service | Component | Dev/Month (USD) | Prod/Month (USD) | Cost Driver | Optimization |
|---|---|---|---|---|---|
| Amazon Bedrock | Investigation (Claude 3.5 Sonnet): ~2 invocations/day × 50K input + 8K output tokens | ~$4 | ~$80 | Token volume | Cache common evidence patterns; use Haiku for Reporting |
| Amazon Bedrock | Reporting (narrative): ~2 invocations/day × 10K tokens | ~$0.50 | ~$5 | Token volume | Use Haiku (~10× cheaper) for narrative only |
| AWS Step Functions | Standard Workflows: ~2 lifecycle SFN × 20 state transitions | ~$0.02 | ~$2 | State transitions | Express Workflows for ingestion pipeline |
| AWS Step Functions | Remediation SFNs: ~2/day × 10 transitions | ~$0.01 | ~$1 | State transitions | — |
| AWS Lambda | All Lambdas: ~50K requests/month, avg 2s, 512MB | ~$1 | ~$15 | GB-seconds | Reduce memory; optimize cold starts |
| Amazon DynamoDB | 9 tables, PAY_PER_REQUEST, ~100K R/W per month | ~$2 | ~$20 | Read/write units | Switch to PROVISIONED with auto-scaling in prod |
| Amazon S3 | Forensic bucket: 1 GB/month (dev), 50 GB/month (prod) + Glacier transitions | ~$0.02 | ~$5 | Storage + Glacier transitions | Lifecycle to Glacier at 90 days |
| Amazon S3 | CloudTrail delivery bucket: 5 GB/month | ~$0.12 | ~$1 | Storage | Lifecycle 90 days |
| Amazon EventBridge | Custom bus: ~10K events/month (dev), ~500K events/month (prod) | ~$0.01 | ~$0.50 | Events published | — |
| Amazon SQS | DLQs: negligible volume | ~$0 | ~$0.10 | API calls | — |
| Amazon SNS | Notifications: ~10 messages/month | ~$0 | ~$0.05 | — | — |
| Amazon API Gateway | Approval endpoint: ~5 requests/month | ~$0 | ~$0.10 | Requests | HTTP API is cheapest |
| AWS KMS | 11 CMKs × $1/month + API calls: ~10K API calls | ~$11 | ~$12 | Key count | Keys are flat-rate — no optimization needed |
| Amazon CloudWatch | Custom metrics: 20 metrics × $0.30; logs ingestion 0.5 GB/month; alarms: 8 × $0.10 | ~$8 | ~$25 | Metrics, logs, alarms | Reduce log verbosity in dev |
| AWS Secrets Manager | 5 secrets × $0.40 | ~$2 | ~$2 | Secret count | — |
| AWS Config | Aggregator: ~50 config items/month | ~$0.005 | ~$5 | Config items recorded | — |
| Amazon GuardDuty | Organization-level: dependent on CloudTrail/DNS volumes | ~$3 | ~$30 | Event volume | Disable in dev if not needed |
| Security Hub | Standard subscription: per finding check | ~$1 | ~$5 | Security checks | — |
| Amazon Security Lake | OCSF VPC Flow Log delivery | ~$2 | ~$15 | Log volume | — |
| **TOTAL (estimate)** | | **~$35** | **~$224** | | |

**Notes:**
- Dev total is well within the USD 50–100 idle budget assumption
- Prod spike during active investigation: Bedrock costs scale linearly with incident volume; a major incident with 50 Bedrock invocations adds ~$100 one-time
- KMS `$1/key/month` flat rate is the largest fixed cost — 11 CMKs = $11/month fixed regardless of usage


---

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system — essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

The CloudSec AI platform contains significant pure-function logic in the Correlation Engine, Safety Validation Engine, Behavior Baseline anomaly detection, Attack Timeline post-processing, Blast Radius calculation, and Report narrative validation layers. These are strong candidates for property-based testing. Infrastructure-as-Code (Terraform), UI rendering, and one-shot side-effect operations (S3 writes, CloudWatch metric emissions, SNS publications) are not suitable for PBT and are tested with example-based or smoke tests instead.

**Library:** [Hypothesis](https://hypothesis.readthedocs.io/en/latest/) for Python (minimum 100 iterations per property by default via `@settings(max_examples=100)`).

---

### Property 1: Incident Severity Reflects Maximum Constituent Finding

*For any* non-empty list of Finding objects with arbitrary severity values (CRITICAL, HIGH, MEDIUM, LOW), the Platform's incident severity assignment function SHALL return the P-level corresponding to the highest severity in the list.

**Validates: Requirements 2.2**

**Test tag:** `Feature: cloudsec-ai, Property 1: Severity reflects maximum finding`

---

### Property 2: Status Transition Enforcement

*For any* `(from_status, to_status)` pair drawn from the full status enum, the transition validation function SHALL accept the pair if and only if it appears in the valid transition set `{(OPEN, INVESTIGATING), (INVESTIGATING, REMEDIATING), (REMEDIATING, VERIFYING), (VERIFYING, RESOLVED), (VERIFYING, ESCALATED)}`, and SHALL reject all other pairs while leaving the current status unchanged.

**Validates: Requirements 2.4, 2.5**

**Test tag:** `Feature: cloudsec-ai, Property 2: Status transitions are strictly enforced`

---

### Property 3: Correlation Engine Assigns Findings to Correct Incidents

*For any* Finding with a known `principal_arn`, `source_ip`, and `resource_arn`, and *for any* set of open Incidents, the Correlation Engine SHALL assign the Finding to an existing Incident if and only if at least one grouping rule (principal+30min, IP+15min, resource+60min) matches, and when multiple incidents match, SHALL select the one with the minimum `creation_timestamp`.

**Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5**

**Test tag:** `Feature: cloudsec-ai, Property 3: Correlation assigns findings correctly`

---

### Property 4: Volume Spike Anomaly Detection Respects 3-Sigma Threshold

*For any* Behavior Baseline with at least 5 qualifying data points for a given hour-of-day, and *for any* observed call count, the anomaly detection function SHALL emit a `VOLUME_SPIKE` signal if and only if the observed count is strictly greater than `mean + 3 * stddev` for that hour-of-day.

**Validates: Requirements 4.4**

**Test tag:** `Feature: cloudsec-ai, Property 4: Volume spike detection respects statistical threshold`

---

### Property 5: Attack Timeline Post-Processing Preserves Only Cited, Ordered Entries

*For any* raw attack timeline array (with arbitrary entries, some with valid `citation_id` values and some with invalid or missing ones), and *for any* evidence bundle, the `post_process_timeline` function SHALL produce an array where (a) every entry has a `citation_id` that appears in the evidence bundle's valid ID set, and (b) entries are sorted in non-decreasing order by `timestamp`.

**Validates: Requirements 6.1, 6.2, 6.3**

**Test tag:** `Feature: cloudsec-ai, Property 5: Timeline post-processing preserves only cited and ordered entries`

---

### Property 6: Blast Radius Risk Score Satisfies Formula and Cap

*For any* combination of `count_sensitive_resources`, `count_assumable_roles`, and `count_confirmed_accessed_resources` (all non-negative integers), the `calculate_risk_score` function SHALL return `min(100, count_sensitive * 20 + count_assumable_roles * 5 + count_confirmed_accessed * 10)`, and the result SHALL always be in the range `[0, 100]`.

**Validates: Requirements 7.4**

**Test tag:** `Feature: cloudsec-ai, Property 6: Blast radius risk score satisfies formula and is capped at 100`

---

### Property 7: Safety Validation Level 3 Conditions Always Override Lower Levels

*For any* remediation recommendation input, if any Level 3 condition is satisfied (unknown action type, invalid ARN pattern, destructive action, P3/P4 severity, confidence < 0.60), the Safety Validation Engine SHALL assign Execution Decision Level 3, regardless of whether Level 1 or Level 2 conditions also apply.

**Validates: Requirements 8.3, 8.4, 8.6, 8.7, 8.8**

**Test tag:** `Feature: cloudsec-ai, Property 7: Level 3 conditions always override lower levels`

---

### Property 8: Safety Validation Rejects Invalid Inputs Before Any Decision

*For any* recommendation input where at least one of the following is true — `action_type` is null, `target_resource_arn` is null or not a valid AWS ARN, `parameters` is null, `confidence_score` is outside `[0.0, 1.0]` — the Safety Validation Engine SHALL raise an `InputValidationError` and SHALL NOT assign any Execution Decision or invoke any Remediation Playbook.

**Validates: Requirements 8.1, 8.5**

**Test tag:** `Feature: cloudsec-ai, Property 8: Invalid inputs are rejected before any decision is assigned`

---

### Property 9: Playbook Idempotency — Same Resource State After Two Executions

*For any* valid Remediation Playbook input (for each of the 6 playbooks), executing the playbook twice with identical input SHALL result in the same target resource protection state after both executions, and both executions SHALL complete without error.

**Validates: Requirements 10.8**

**Test tag:** `Feature: cloudsec-ai, Property 9: Playbook execution is idempotent`

---

### Property 10: Knowledge Base Anonymization Removes All Original Account Identifiers

*For any* incident data dictionary containing arbitrary AWS account IDs (12-digit numbers) and IAM ARNs, the `anonymize_for_knowledge_base` function SHALL produce an output where no 12-digit account ID pattern and no `arn:aws` ARN pattern from the original data appears verbatim.

**Validates: Requirements 13.7**

**Test tag:** `Feature: cloudsec-ai, Property 10: Knowledge base anonymization removes all original account identifiers`

---

### Property 11: Report Narrative Validation Correctly Identifies Unauthorized Identifiers

*For any* Bedrock-generated narrative string and *for any* evidence bundle, the narrative validation function SHALL flag the narrative as containing unauthorized identifiers if and only if the narrative contains at least one IAM principal ARN, AWS account ID, or resource ARN that does not appear in the evidence bundle's identifier set.

**Validates: Requirements 14.4, 14.5**

**Test tag:** `Feature: cloudsec-ai, Property 11: Narrative validation correctly identifies unauthorized identifiers`

---

## Error Handling

### 33.1 Lambda Error Handling Standard

All Lambda functions follow this error handling pattern:

```python
def handler(event, context):
    try:
        # Structured entry logging
        logger.info({
            "incident_id": event.get("incident_id"),
            "message": "Lambda invoked",
            "function_name": context.function_name
        })
        
        result = process(event)
        return result
        
    except InputValidationError as e:
        logger.error({"message": "Input validation failed", "error": str(e)})
        raise  # Let Step Functions handle the error type
        
    except boto3.exceptions.Boto3Error as e:
        logger.error({"message": "AWS API error", "error": str(e)})
        cloudwatch.put_metric_data(...)  # appropriate metric
        raise  # Allow SFN retry logic to apply
        
    except Exception as e:
        logger.error({"message": "Unexpected error", "error": str(e)})
        raise
```

### 33.2 Step Functions Error Handling Strategy

All Step Functions tasks use structured error handling:
- **Retryable errors** (transient AWS API failures): retry up to 2 times with exponential backoff starting at 5 seconds
- **Non-retryable errors** (input validation, schema failures): catch immediately, route to appropriate failure state
- **Unhandled errors**: catch `States.ALL`, route to `EscalateIncident` state

### 33.3 DynamoDB Write Failures

For Incident and Remediation Decision writes specifically:
- Retry up to 3 times with exponential backoff starting at 1 second (Req 2.9)
- All retries exhausted → emit error event to SNS topic with Incident ID and failed operation
- Audit trail write failure for remediation decisions → BLOCKING error (do not invoke playbook)

### 33.4 Cross-Account AssumeRole Failures

- Investigation Lambda: proceed with partial evidence; annotate `PARTIAL_EVIDENCE: true`
- Blast Radius Lambda: use static policy analysis fallback; annotate `analysis_method: STATIC_FALLBACK`
- Remediation Lambda: fail the playbook step; transition Incident to ESCALATED; log failure reason

---

## Testing Strategy

### 34.1 Approach

CloudSec AI uses a dual testing approach combining example-based unit tests and property-based tests for pure function logic.

**Unit tests** (pytest + moto):
- All Lambda handlers
- Pure functions: correlation logic, safety validation decision logic, timeline post-processing, risk score formula, anonymization
- Minimum 80% line coverage per Lambda

**Property-based tests** (Hypothesis, minimum 100 iterations per property):
- Properties 1–11 as defined in Section 32
- Run in CI pipeline on every PR

**Integration tests** (moto + local DynamoDB):
- End-to-end flow: Finding ingestion → Incident creation in OPEN status
- JSON Schema validation: valid and invalid report structures
- Idempotency: each playbook invoked twice

**Infrastructure tests** (terraform validate + tflint):
- All Terraform modules pass `terraform validate`
- All modules pass `tflint --recursive`
- Run in CI pipeline before every apply

**Smoke tests** (manual or CI with localstack):
- S3 bucket configuration (versioning, encryption, bucket policy)
- DynamoDB table encryption settings
- CloudWatch alarm configurations

### 34.2 CI/CD Testing Pipeline

```
PR → 
  1. terraform validate (all modules)
  2. tflint (all modules)
  3. pytest (unit tests + property tests + integration tests)
  4. Coverage check (≥80% per Lambda)
  5. Schema validation tests
  6. Idempotency tests
  
Merge to main →
  7. terraform plan (dev environment)
  8. Security scan (bandit, safety)
  9. Deploy to dev (terraform apply)
```

---

## 35. Traceability Matrix

| Requirement | Component | AWS Service | Security Control | Test Coverage |
|---|---|---|---|---|
| Req 1.1 — GuardDuty ingestion | GD Ingestion Lambda + EventBridge Rule | GuardDuty, EventBridge | IAM role scoped to `events:PutEvents` only | Unit test: `test_guardduty_event_normalized` |
| Req 1.2 — Security Hub severity filter | SH Ingestion Lambda + EventBridge Rule | Security Hub, EventBridge | EventBridge rule pattern filters LOW/INFORMATIONAL | Unit test: `test_severity_filter` |
| Req 1.3 — CloudTrail org-level trail | Terraform `telemetry-ingestion` module | CloudTrail, S3 | CloudTrail log validation, S3 encryption | Terraform validate + smoke test |
| Req 1.4 — VPC Flow Logs via Security Lake | Terraform `security-lake` module | Security Lake, VPC | VPC tag-based delivery | Terraform validate |
| Req 1.5 — Config aggregator | Terraform `telemetry-ingestion` module | AWS Config | Config aggregator org-level | Terraform validate |
| Req 1.6 — Telemetry lag metric | Lag Monitor Lambda | CloudWatch | Scheduled Lambda; metric per source | Unit test: `test_lag_metric_emission` |
| Req 1.7 — DLQ for parse failures | SQS DLQ + Ingestion Lambda | SQS | DLQ KMS encryption; 14-day retention | Smoke test; unit test: `test_parse_failure_routes_to_dlq` |
| Req 1.8 — Tag ingested events | All Ingestion Lambdas | DynamoDB | Tagging at write time | Unit test: `test_event_tagging` |
| Req 2.1 — Incident creation in 10s | Correlation Lambda + Step Functions | DynamoDB, Step Functions | DynamoDB conditional write (no duplicates) | Integration test: `test_e2e_incident_creation` |
| Req 2.2 — Severity from highest finding | Incident creation logic | DynamoDB | — | **Property 1** |
| Req 2.3 — Status update in 5s | Lifecycle SFN Lambda steps | Step Functions, DynamoDB | DynamoDB write with retries | Unit test |
| Req 2.4 — Valid status transitions only | Status Transition Lambda | DynamoDB | Condition expression on write | **Property 2** |
| Req 2.5 — Reject invalid transitions | Status Transition Lambda | DynamoDB | Raise error, preserve status | **Property 2** |
| Req 2.6 — ESCALATED with SNS on verification failure | Verification Lambda | SNS | IAM role scoped to specific SNS topic | Unit test |
| Req 2.7 — 365-day DynamoDB retention | DynamoDB TTL config | DynamoDB | TTL epoch calculation | Terraform validate |
| Req 2.8 — Resolution timestamp | Resolution Lambda | DynamoDB | — | Unit test |
| Req 2.9 — DynamoDB retry with backoff | All write-path Lambdas | DynamoDB | Retry logic with exponential backoff | Unit test |
| Req 3.1-3.3 — Correlation grouping rules | Correlation Lambda | DynamoDB | Atomic DynamoDB conditional writes | **Property 3** |
| Req 3.4 — Oldest matching incident | Correlation Lambda | DynamoDB | Sort by creation_timestamp | **Property 3** |
| Req 3.5 — New incident if no match | Correlation Lambda | DynamoDB, Step Functions | — | Integration test |
| Req 3.6 — CorrelationDecision record | Correlation Lambda | DynamoDB | — | Unit test |
| Req 3.7 — 10s correlation SLA | Correlation Lambda | EventBridge, DynamoDB | Lambda reserved concurrency | Integration test |
| Req 4.1-4.2 — Baseline computation | Behavior Baseline Lambda | DynamoDB, CloudTrail | — | Unit test |
| Req 4.3-4.6 — Anomaly signal types | Behavior Baseline Lambda | EventBridge | — | Unit test (per anomaly type) |
| Req 4.4 — Volume spike (3σ) | Behavior Baseline Lambda | — | — | **Property 4** |
| Req 4.7-4.8 — LOW_BASELINE_CONFIDENCE flag | Behavior Baseline Lambda | — | — | Unit test |
| Req 5.1-5.2 — Evidence bundle assembly | Investigation Lambda | S3, DynamoDB, CloudTrail | PARTIAL_EVIDENCE flag | Unit test |
| Req 5.3-5.4 — Bedrock prompt and timeout | Investigation Lambda | Bedrock | 30s timeout; system prompt injection prevention | Unit test (mock Bedrock) |
| Req 5.5 — Schema validation | Investigation Lambda | — | JSON Schema validator | **JSON Schema validation tests** |
| Req 5.6-5.7 — Retry and escalation on failure | Investigation Lambda | CloudWatch, S3 | BedrockSchemaFailure metric | Unit test |
| Req 5.9 — confidence_score in [0,1] | Investigation Lambda / JSON Schema | — | — | **JSON Schema validation tests** |
| Req 5.11 — MITRE citation validation | Investigation Lambda | — | — | **JSON Schema + custom validation tests** |
| Req 5.12 — Platform Investigation Schema | Platform Investigation Schema (Section 10) | — | — | **JSON Schema validation tests** |
| Req 5.13 — No credentials in Bedrock prompt | Investigation Lambda | Bedrock | Prompt construction excludes secrets | Unit test (prompt content inspection) |
| Req 6.1-6.5 — Attack timeline | Timeline post-processing | — | Citation cross-reference | **Property 5** |
| Req 7.1-7.2 — IAM Policy Simulator | Blast Radius Lambda | IAM | Cross-account read role | Unit test (mock IAM Simulator) |
| Req 7.4 — Risk score formula | Blast Radius Lambda | — | — | **Property 6** |
| Req 7.5 — Attack path enumeration (cycle detection) | Blast Radius Lambda | — | — | Unit test |
| Req 7.7 — Static fallback | Blast Radius Lambda | IAM | Fallback annotation | Unit test |
| Req 8.1 — Input validation | Safety Validation Lambda | — | — | **Property 8** |
| Req 8.3-8.8 — Decision level logic | Safety Validation Lambda | — | — | **Property 7** |
| Req 8.9-8.10 — Audit write and blocking | Safety Validation Lambda | DynamoDB, CloudWatch | Audit failure blocks execution | Unit test + **Negative test** |
| Req 9.1-9.9 — Approval workflow | Approval Lambda, API Gateway | API Gateway, SFN, DynamoDB, SNS | Pre-signed URL, self-approval check, expiry | Unit test (all validation cases) |
| Req 10.1-10.6 — Playbook execution | 6 Remediation Playbooks SFN | Step Functions, IAM | Cross-account role scoped to playbook actions | Integration test (mock) |
| Req 10.8 — Playbook idempotency | Remediation Playbooks | — | Check-and-skip pattern | **Property 9** + **Idempotency tests** |
| Req 10.9-10.10 — Playbook failure handling | Remediation Playbooks | CloudWatch, Step Functions | Forensic evidence not overwritten | Unit test |
| Req 11.1-11.7 — Verification Engine | Verification Lambda | IAM, EC2, S3, CloudTrail | Cross-account read role | Unit test (per playbook check) |
| Req 12.1-12.10 — Forensic evidence | S3 bucket + writing Lambdas | S3, KMS | Object Lock (prod), versioning, encryption | Smoke test + `terraform validate` |
| Req 13.1-13.8 — Knowledge Base | Knowledge Base Lambda + DynamoDB | DynamoDB | Entry gate; PII redaction | **Property 10** + Unit test |
| Req 14.1-14.8 — Reporting Engine | Reporting Lambda | Bedrock, S3 | Narrative validation | **Property 11** + Unit test |
| Req 15.1-15.8 — Observability | Observability Terraform module | CloudWatch, Budgets | — | Smoke test + `terraform validate` |
| Req 16.1-16.10 — IAM design | All IAM roles (Terraform) | IAM | No wildcard actions; per-table CMK | `terraform validate`; IAM policy linting |
| Req 17.1-17.7 — Multi-account architecture | All modules + cross-account-roles module | Organizations, CloudTrail, Config | Cross-account role trust policies | `terraform validate` |
| Req 18.1-18.6 — Infrastructure as Code | All Terraform modules | — | `terraform validate`, `tflint`, no hard-coded values | **Terraform validation tests** |
| Req 19.1-19.6 — Testing | Test suite | — | — | CI pipeline |
| Req 20.1-20.5 — Attack simulations | attack-simulations/ scripts | STS | Account guard check | Unit test: `test_account_guard_exits_on_wrong_account` |

