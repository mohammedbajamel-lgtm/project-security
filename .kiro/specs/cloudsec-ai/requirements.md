# Requirements Document

## Introduction

CloudSec AI is an AWS-native security platform that automates the full incident response lifecycle: Detect → Investigate → Correlate → Understand → Decide → Contain/Fix → Verify → Report. The platform ingests security signals from AWS GuardDuty, Security Hub, CloudTrail, VPC Flow Logs, AWS Config, and Amazon Security Lake; uses Amazon Bedrock to correlate evidence, reconstruct attack timelines, calculate blast radius, and produce structured remediation recommendations; executes approved remediation playbooks through a deterministic safety-validation layer; verifies remediation success; and generates a final AI-authored incident report. The architecture is multi-account (AWS Organizations), Terraform-managed, serverless-first, and built for a personal portfolio demonstration of production-grade AWS security engineering.

**Assumptions:**
- MVP targets a two-account layout (Security Account + one Workload Account) but the architecture must support expansion to the full organization model without rework.
- Bedrock model selection defaults to Anthropic Claude 3.5 Sonnet unless a different model is specified in configuration; model ID is not hard-coded.
- Attack simulations run only in a dedicated, isolated lab environment and never against production resources.
- Cost budget for the MVP is approximately USD 50–100/month at idle; active investigation workloads may spike above this and are acceptable.
- Behavior baselines are seeded from 30 days of historical CloudTrail data where available; shorter windows are accepted with reduced confidence signaling.

---

## Glossary

- **Platform**: The CloudSec AI system as a whole.
- **Security Account**: The centralized AWS account that hosts all Platform infrastructure and receives findings from all Workload Accounts.
- **Workload Account**: Any AWS account monitored by the Platform (Production, Development, or other).
- **Finding**: A discrete security signal produced by GuardDuty, Security Hub, or a custom detection rule.
- **Incident**: A Platform-managed record created when one or more correlated Findings meet an escalation threshold.
- **Investigation**: The automated AI-driven analysis phase that produces a structured Investigation Report for a given Incident.
- **Investigation Report**: The machine-readable JSON artifact produced by the AI Investigation Engine, validated against the Platform Investigation Schema.
- **Platform Investigation Schema**: The JSON Schema document that defines the required structure and fields of an Investigation Report.
- **AI Investigation Engine**: The Lambda-based component that invokes Amazon Bedrock, constructs prompts from evidence, and validates the model response against the Platform Investigation Schema.
- **Safety Validation Engine**: The deterministic code component that receives a remediation recommendation, checks it against the Approved Action Policy, and produces an Execution Decision.
- **Approved Action Policy**: The machine-readable list of permissible remediation actions, their allowed parameter ranges, and their applicability conditions.
- **Execution Decision**: The Safety Validation Engine output classifying a remediation recommendation as Level 1 (automatic), Level 2 (approval required), or Level 3 (recommendation only).
- **Remediation Playbook**: A versioned, deterministic Step Functions state machine that executes one specific containment or remediation action against an AWS resource.
- **Verification Engine**: The component that re-queries affected resources after remediation and confirms that the Incident is resolved.
- **Forensic Evidence Package**: The encrypted, versioned S3 archive preserving all artifacts for a given Incident.
- **Blast Radius Report**: The structured output describing the set of resources, roles, and permissions reachable from a compromised identity.
- **Behavior Baseline**: The statistical profile of normal AWS API activity for a principal, derived from historical CloudTrail data.
- **MITRE ATT&CK Mapping**: The assignment of one or more MITRE ATT&CK for Cloud technique IDs to observed attacker behavior.
- **Confidence Score**: A numeric value in the range [0.0, 1.0] representing the AI Investigation Engine's certainty in a conclusion.
- **Incident Knowledge Base**: The DynamoDB table storing confirmed, verified past Incidents and their remediation outcomes for use in future Investigations.
- **Approval Workflow**: The human-in-the-loop process by which a designated approver reviews and accepts or rejects a Level 2 Execution Decision.
- **Cost Alarm**: A CloudWatch Billing Alarm or AWS Budgets alert that fires when estimated spend exceeds a configured threshold.
- **Terraform Module**: A reusable, parameterized infrastructure component managed with Terraform.
- **Lab Environment**: The isolated AWS account used exclusively for safe attack simulations; it shares no IAM trust or network connectivity with Production or Security Accounts.

---

## Requirements

---

### Requirement 1: Security Telemetry Ingestion

**User Story:** As a security engineer, I want the Platform to continuously ingest security signals from all supported AWS telemetry sources, so that no relevant security event is missed.

#### Acceptance Criteria

1. THE Platform SHALL ingest Findings from Amazon GuardDuty in the Security Account via an Amazon EventBridge rule that matches all GuardDuty Finding events.
2. THE Platform SHALL ingest Findings from AWS Security Hub in the Security Account via an Amazon EventBridge rule that matches Security Hub findings with severity MEDIUM, HIGH, or CRITICAL, and SHALL exclude findings with severity LOW or INFORMATIONAL from ingestion.
3. THE Platform SHALL ingest AWS CloudTrail management events from all Workload Accounts via a multi-region, organization-level CloudTrail trail that delivers logs to an S3 bucket in the Security Account.
4. THE Platform SHALL ingest VPC Flow Logs from VPCs in all Workload Accounts that carry a platform monitoring tag, delivering logs to Amazon Security Lake in the Security Account.
5. THE Platform SHALL ingest AWS Config configuration change notifications from all Workload Accounts via an AWS Config aggregator in the Security Account.
6. WHEN no events are received from a telemetry source for more than 15 consecutive minutes, THE Platform SHALL emit a CloudWatch metric named `TelemetryIngestionLag` with a dimension identifying the source name.
7. IF an ingested event cannot be parsed into the Platform event schema, THEN THE Platform SHALL route the raw event to a Dead Letter Queue with a retention period of at least 14 days and emit a `ParseFailure` CloudWatch metric increment for that event.
8. THE Platform SHALL tag all ingested events with the source account ID, source region, and the timestamp at which the Platform received the event, before storing them.

---

### Requirement 2: Incident Creation and Lifecycle Management

**User Story:** As a security engineer, I want the Platform to create, track, and manage Incidents from detection through resolution, so that every security event has a complete, auditable lifecycle record.

#### Acceptance Criteria

1. WHEN one or more correlated Findings meet the escalation threshold defined in the Correlation Engine, THE Platform SHALL create an Incident record in DynamoDB with a unique Incident ID, severity, status `OPEN`, creation timestamp (UTC, ISO 8601), and list of associated Finding IDs, and SHALL complete this creation within 10 seconds of the threshold being met.
2. THE Platform SHALL assign severity to each Incident using the highest severity among its constituent Findings, mapped as: CRITICAL → P1, HIGH → P2, MEDIUM → P3, LOW → P4.
3. WHILE an Incident has status `OPEN` or `INVESTIGATING`, THE Platform SHALL update the Incident record in DynamoDB within 5 seconds of any status transition.
4. THE Platform SHALL enforce the following valid status transitions only: `OPEN` → `INVESTIGATING`, `INVESTIGATING` → `REMEDIATING`, `REMEDIATING` → `VERIFYING`, `VERIFYING` → `RESOLVED`, and `VERIFYING` → `ESCALATED`.
5. IF a status transition is attempted that does not match a valid transition defined in criterion 4, THEN THE Platform SHALL reject the transition, preserve the current Incident status unchanged, and return an error indicating the invalid transition.
6. IF the Verification Engine determines that remediation did not succeed, THEN THE Platform SHALL transition the Incident status to `ESCALATED` and publish a notification to the configured SNS topic containing the Incident ID, severity, and failure reason within 30 seconds of the determination.
7. THE Platform SHALL retain Incident records in DynamoDB for a minimum of 365 days from the creation timestamp, after which records MAY be archived or deleted.
8. WHEN an Incident reaches status `RESOLVED` or `ESCALATED`, THE Platform SHALL record the resolution timestamp (UTC, ISO 8601) and the total time-to-resolve duration in seconds in the Incident record.
9. IF DynamoDB is unavailable when the Platform attempts to create or update an Incident record, THEN THE Platform SHALL retry the operation up to 3 times with exponential backoff starting at 1 second, and if all retries fail, SHALL emit an error event to the configured SNS topic indicating the Incident ID and failed operation type.

---

### Requirement 3: Finding Correlation Engine

**User Story:** As a security analyst, I want the Platform to group related Findings into a single Incident, so that I can investigate an attack as a whole rather than as disconnected alerts.

#### Acceptance Criteria

1. IF a Finding shares the same AWS principal ARN as at least one Finding already associated with an open Incident and its timestamp falls within 30 minutes of the most recently added Finding in that Incident, THEN THE Correlation Engine SHALL add the new Finding to that existing Incident.
2. IF a Finding shares the same source IP address as at least one Finding already associated with an open Incident and its timestamp falls within 15 minutes of the most recently added Finding in that Incident, THEN THE Correlation Engine SHALL add the new Finding to that existing Incident.
3. IF a Finding involves the same AWS resource ARN as at least one Finding already associated with an open Incident, regardless of the principal, and its timestamp falls within 60 minutes of the most recently added Finding in that Incident, THEN THE Correlation Engine SHALL add the new Finding to that existing Incident.
4. IF a new Finding matches more than one open Incident by the grouping rules in criteria 1–3, THEN THE Correlation Engine SHALL add the Finding to the oldest matching open Incident, as determined by creation timestamp.
5. IF a Finding does not match any existing open Incident by any grouping rule in criteria 1–3, THEN THE Correlation Engine SHALL create a new Incident containing only that Finding.
6. WHEN the Correlation Engine assigns a Finding to an Incident, THE Correlation Engine SHALL write a `CorrelationDecision` record to DynamoDB containing the Finding ID, the Incident ID, the timestamp of the EventBridge event receipt, and all grouping rules that matched.
7. WHEN the Correlation Engine receives a Finding from the EventBridge event bus, THE Correlation Engine SHALL complete assignment to an Incident or creation of a new Incident within 10 seconds of the EventBridge event receipt timestamp.

---

### Requirement 4: Behavior Baseline System

**User Story:** As a security analyst, I want the Platform to maintain a statistical baseline of normal AWS API activity for each principal, so that anomalous behavior can be detected with deterministic signals rather than relying solely on AI judgment.

#### Acceptance Criteria

1. THE Behavior Baseline System SHALL compute a baseline profile for each AWS principal ARN observed in CloudTrail, tracking: the set of AWS regions used, the distribution of API call counts by hour-of-day, the set of AWS service namespaces called, the set of IAM roles assumed, and the set of top-20 most-called API actions.
2. THE Behavior Baseline System SHALL update each principal's baseline profile daily using a tumbling 30-day window of CloudTrail data, excluding days on which the principal performed fewer than 10 API calls.
3. WHEN a principal performs an API call in a region not present in that principal's baseline profile, THE Behavior Baseline System SHALL emit an `AnomalySignal` event to the Platform event bus with type `NEW_REGION`, including the principal ARN and the triggering region name.
4. WHEN a principal performs an API call volume in a single UTC calendar hour that exceeds 3 standard deviations above the mean for that hour-of-day in that principal's baseline, AND the baseline contains at least 5 qualifying data points for that hour-of-day, THE Behavior Baseline System SHALL emit an `AnomalySignal` event to the Platform event bus with type `VOLUME_SPIKE`, including the principal ARN and the observed call count.
5. WHEN a principal assumes a role not present in that principal's baseline profile, THE Behavior Baseline System SHALL emit an `AnomalySignal` event to the Platform event bus with type `NEW_ROLE_ASSUMPTION`, including the principal ARN and the assumed role ARN.
6. WHEN a principal calls an API action in the `iam:`, `sts:`, or `organizations:` namespace that is not present in that principal's baseline profile, THE Behavior Baseline System SHALL emit an `AnomalySignal` event to the Platform event bus with type `NEW_SENSITIVE_API`, including the principal ARN and the API action name.
7. IF a principal's baseline profile contains fewer than 7 days that meet the qualifying threshold from criterion 2, THEN THE Behavior Baseline System SHALL attach a `LOW_BASELINE_CONFIDENCE` flag to any `AnomalySignal` it emits for that principal.
8. IF a principal ARN is observed in CloudTrail but no baseline profile exists for that principal yet, THEN THE Behavior Baseline System SHALL treat the principal as having zero qualifying days and SHALL attach a `LOW_BASELINE_CONFIDENCE` flag to any `AnomalySignal` emitted for that principal until 7 qualifying days have been accumulated.
9. THE Behavior Baseline System SHALL store all baseline profiles in DynamoDB with a TTL of 90 days from last update.

---

### Requirement 5: AI Investigation Engine

**User Story:** As a security analyst, I want the Platform to use Amazon Bedrock to correlate evidence, reconstruct attacker behavior, and produce structured findings, so that I receive a deep investigation rather than a log summary.

#### Acceptance Criteria

1. WHEN an Incident transitions to status `INVESTIGATING`, THE AI Investigation Engine SHALL assemble an evidence bundle containing: all associated CloudTrail events, all associated Findings, all associated `AnomalySignal` events, the principal's Behavior Baseline profile, and the relevant AWS Config snapshots for affected resources.
2. IF the evidence bundle assembly fails due to an unavailable data source, THEN THE AI Investigation Engine SHALL proceed with the available evidence, annotate the Investigation Report with a `PARTIAL_EVIDENCE` flag identifying the missing sources, and continue to Bedrock invocation.
3. THE AI Investigation Engine SHALL construct a prompt that instructs the Bedrock model to: correlate the provided evidence, reconstruct an attack timeline with timestamps derived only from the provided events, identify the likely initial access vector, identify any privilege escalation steps, identify any persistence mechanisms, identify any data access or exfiltration indicators, identify affected principals and resource ARNs, and produce a MITRE ATT&CK mapping citing specific evidence for each technique.
4. THE AI Investigation Engine SHALL instruct the Bedrock model to produce output exclusively in the JSON structure defined by the Platform Investigation Schema, and SHALL enforce a 30-second timeout per Bedrock invocation attempt.
5. WHEN the Bedrock model returns a response, THE AI Investigation Engine SHALL validate the response against the Platform Investigation Schema using a JSON Schema validator before accepting the response.
6. IF the Bedrock model response fails Platform Investigation Schema validation, THEN THE AI Investigation Engine SHALL retry the invocation up to 2 additional times with a prompt that includes the validation error details.
7. IF all 3 Bedrock invocation attempts produce schema-invalid responses, THEN THE AI Investigation Engine SHALL set the Incident status to `ESCALATED`, store all raw model responses in the Forensic Evidence Package, and emit a `BedrockSchemaFailure` CloudWatch metric.
8. WHEN an Investigation Report is accepted, THE AI Investigation Engine SHALL transition the Incident to `INVESTIGATING` complete and update the Incident record with the Investigation Report S3 reference within 10 seconds.
9. THE AI Investigation Engine SHALL include in every Investigation Report a `confidence_score` field with a value in the range [0.0, 1.0], where the score reflects the completeness and consistency of the evidence provided.
10. THE AI Investigation Engine SHALL include in every Investigation Report an `evidence_citations` array in which each conclusion references one or more specific CloudTrail `eventID` values or Finding IDs present in the evidence bundle.
11. THE AI Investigation Engine SHALL reject any Investigation Report that contains a MITRE ATT&CK technique claim not supported by at least one cited `eventID` or Finding ID; such rejection counts against the retry budget.
12. THE Platform Investigation Schema SHALL define the following top-level fields as required: `incident_id`, `confidence_score`, `attack_timeline`, `initial_access_assessment`, `privilege_escalation_indicators`, `persistence_indicators`, `data_access_indicators`, `affected_principals`, `affected_resources`, `mitre_attack_mapping`, `evidence_citations`, `blast_radius_summary`, `remediation_recommendations`.
13. THE AI Investigation Engine SHALL not pass credentials, KMS key material, or the contents of secrets to the Bedrock model.

---

### Requirement 6: Attack Timeline Reconstruction

**User Story:** As a security analyst, I want the Platform to reconstruct a chronological attack timeline from raw API events, so that I can understand the sequence and progression of attacker activity.

#### Acceptance Criteria

1. WHEN an investigation completes, THE AI Investigation Engine SHALL produce an `attack_timeline` array in the Investigation Report where each entry contains the following fields in ascending chronological order by event timestamp: an ISO 8601 timestamp, a description naming the observed AWS API call and the type of action it represents, the AWS principal ARN that performed the action, the AWS API call name that was observed, the resource ARN affected (set to null if not present in the source event), and the evidence citation (CloudTrail `eventID` or Finding ID).
2. WHEN an investigation completes, THE AI Investigation Engine SHALL include in the `attack_timeline` only entries for which a directly matching event exists in the evidence bundle identified by a non-null `eventID` or Finding ID; entries without a citation SHALL be excluded from the array.
3. IF the evidence bundle contains no events, THEN THE AI Investigation Engine SHALL produce an `attack_timeline` as an empty array in the Investigation Report.
4. WHEN the `attack_timeline` contains two or more entries from different AWS accounts, THE AI Investigation Engine SHALL annotate each entry with the source AWS account ID.
5. WHEN the `attack_timeline` is produced and two consecutive entries attributed to the same principal ARN have timestamps more than 60 minutes apart, THE AI Investigation Engine SHALL insert a `TIMELINE_GAP` annotation between those two entries recording the principal ARN and the duration of the gap in minutes.

---

### Requirement 7: Blast Radius Analysis

**User Story:** As a security analyst, I want the Platform to calculate the blast radius of a compromised identity, so that I can understand the full scope of potential attacker reach.

#### Acceptance Criteria

1. WHEN an Investigation Report is produced for an Incident involving a compromised IAM principal, THE Blast Radius Analyzer SHALL enumerate all IAM roles that the compromised principal can assume using `sts:AssumeRole`, using the IAM Policy Simulator API or equivalent deterministic policy evaluation.
2. WHEN an Investigation Report is produced for an Incident involving a compromised IAM principal, THE Blast Radius Analyzer SHALL enumerate all AWS resource ARNs the compromised principal has direct `Allow` permissions on, as determined by policy analysis, and classify each resource as `CONFIRMED_ACCESSED` if a CloudTrail data-plane event (e.g., `GetObject`, `Invoke`, `GetItem`) for that resource appears in the evidence bundle within a 90-day lookback window, or `REACHABLE_NOT_CONFIRMED` otherwise.
3. WHEN an Investigation Report is produced, THE Blast Radius Analyzer SHALL identify all resources tagged with `Sensitivity: HIGH` or `Sensitivity: CRITICAL` that appear in the reachable resource set and include them in a `sensitive_resources` array.
4. WHEN an Investigation Report is produced, THE Blast Radius Analyzer SHALL calculate a numeric blast radius risk score in the range [0, 100] using the formula: `min(100, count_of_sensitive_resources * 20 + count_of_assumable_roles * 5 + count_of_confirmed_accessed_resources * 10)`.
5. WHEN an Investigation Report is produced, THE Blast Radius Analyzer SHALL include a `potential_attack_paths` array of up to 20 entries, each describing a role-chaining sequence of up to 3 hops from the compromised principal, with cycle detection to prevent infinite loops.
6. WHEN an Investigation Report is produced, THE Blast Radius Analyzer SHALL populate the `blast_radius_summary` field of the Investigation Report with: `risk_score`, `confirmed_accessed_resources`, `reachable_not_confirmed_resources`, `sensitive_resources`, `assumable_roles`, and `potential_attack_paths`.
7. IF the IAM Policy Simulator API returns a non-2xx response or does not respond within 30 seconds, THEN THE Blast Radius Analyzer SHALL fall back to static analysis of the attached and inline policies retrieved via `iam:GetPolicy` and `iam:GetPolicyVersion`, and SHALL annotate the result with `analysis_method: STATIC_FALLBACK`.

---

### Requirement 8: Safety Validation Engine

**User Story:** As a security engineer, I want all AI-recommended remediation actions to pass through a deterministic safety check before any execution, so that the AI can never directly trigger AWS API calls.

#### Acceptance Criteria

1. WHEN a remediation recommendation is received, THE Safety Validation Engine SHALL validate that the input contains a non-null action type, a non-null target resource ARN conforming to the AWS ARN format, a non-null parameters object, and a confidence score in the range [0.0, 1.0] before performing any further evaluation.
2. WHEN a remediation recommendation passes input validation, THE Safety Validation Engine SHALL validate each recommendation against the Approved Action Policy before assigning an Execution Decision.
3. IF a recommendation's action type is not present in the Approved Action Policy, THEN THE Safety Validation Engine SHALL assign Execution Decision Level 3 (recommendation only) and SHALL NOT invoke any Remediation Playbook.
4. IF a recommendation's target resource ARN does not match an allowed ARN pattern in the Approved Action Policy, THEN THE Safety Validation Engine SHALL assign Execution Decision Level 3.
5. IF a recommendation input fails the validation in criterion 1, THEN THE Safety Validation Engine SHALL reject the recommendation, record the rejection reason in DynamoDB, and SHALL NOT assign any Execution Decision or invoke any Remediation Playbook.
6. WHEN assigning an Execution Decision, THE Safety Validation Engine SHALL evaluate Level 3 conditions first, then Level 2, and finally Level 1, assigning the highest-severity applicable level. THE Safety Validation Engine SHALL assign Execution Decision Level 1 (automatic) only when: the action is classified as reversible in the Approved Action Policy, the Incident severity is P1 or P2, the AI confidence score is in the range [0.85, 1.0], and the target resource is not tagged `CriticalityTier: PROD`, AND no Level 2 or Level 3 condition applies.
7. THE Safety Validation Engine SHALL assign Execution Decision Level 2 (approval required) when: the action is classified as disruptive in the Approved Action Policy, OR the Incident severity is P1 or P2 with confidence score in the range [0.60, 0.85), OR the target resource is tagged `CriticalityTier: PROD`, AND no Level 3 condition applies.
8. THE Safety Validation Engine SHALL assign Execution Decision Level 3 when: the action is classified as destructive in the Approved Action Policy, OR the Incident severity is P3 or P4, OR the confidence score is in the range [0.0, 0.60).
9. WHEN an Execution Decision is assigned, THE Safety Validation Engine SHALL record in DynamoDB: Incident ID, recommendation hash, decision level, decision timestamp, and the specific Approved Action Policy rule that was applied.
10. IF the DynamoDB write in criterion 9 fails, THEN THE Safety Validation Engine SHALL NOT invoke any Remediation Playbook and SHALL emit a `RemediationDecisionAuditFailure` CloudWatch metric, treating the audit failure as a blocking error.
11. WHEN an Execution Decision is assigned, THE Safety Validation Engine SHALL emit a `RemediationDecision` CloudWatch metric with a dimension for decision level.

---

### Requirement 9: Human Approval Workflow

**User Story:** As a security engineer, I want Level 2 remediation actions to require explicit human approval before execution, so that potentially disruptive actions are never automated without oversight.

#### Acceptance Criteria

1. WHEN the Safety Validation Engine assigns Execution Decision Level 2, THE Approval Workflow SHALL send a notification to the configured SNS topic containing: Incident ID, severity, affected resource ARN, proposed action, AI justification, confidence score, and a pre-signed approval URL with a 4-hour expiry.
2. WHEN an approver submits an approval response via the pre-signed URL, THE Approval Workflow SHALL record the approver's IAM principal ARN, decision (APPROVED or REJECTED), timestamp, and optional comment (maximum 1000 characters) in the Incident record within 10 seconds of submission.
3. IF an approver does not respond within the approval window of 4 hours, THEN THE Approval Workflow SHALL transition the Incident to `ESCALATED` status and send a notification to the configured SNS topic containing the Incident ID, severity, affected resource ARN, and the reason indicating approval timeout.
4. WHEN an approver submits a REJECTED decision, THE Approval Workflow SHALL record the rejection in the Incident record and SHALL NOT invoke the associated Remediation Playbook, leaving the Incident in `REJECTED` status.
5. WHEN an approver submits an APPROVED decision, THE Approval Workflow SHALL invoke the associated Remediation Playbook within 60 seconds and transition the Incident to `APPROVED` status.
6. IF the pre-signed URL token does not match the Incident ID stored in DynamoDB, THEN THE Approval Workflow SHALL reject the submission with an error indicating an invalid or expired token and SHALL NOT record any approval decision or modify the Incident record.
7. IF the IAM principal ARN of the approver matches the IAM principal ARN recorded as the Incident creator, THEN THE Approval Workflow SHALL reject the submission with an error indicating a self-approval conflict and SHALL NOT record the decision or invoke the Remediation Playbook.
8. IF the pre-signed approval URL is submitted after the 4-hour expiry window, THEN THE Approval Workflow SHALL reject the submission with an error indicating the token has expired and SHALL NOT record any approval decision or modify the Incident record.
9. IF the Incident has already received a recorded decision of APPROVED or REJECTED, THEN THE Approval Workflow SHALL reject any subsequent approval submission for that Incident with an error indicating the decision is already recorded and SHALL NOT modify the existing Incident record.

---

### Requirement 10: Remediation Playbooks

**User Story:** As a security engineer, I want the Platform to execute pre-defined, versioned remediation playbooks, so that containment actions are repeatable, auditable, and safe.

#### Acceptance Criteria

1. WHEN Remediation Playbook 1 (Compromised IAM Credential) is executed with a target principal ARN and Incident ID, THE Playbook SHALL attach an explicit `Deny *` IAM inline policy named `cloudsec-quarantine-{incident_id}` to the compromised principal, delete the virtual MFA device for that principal if one exists and is active, and record the policy ARN in the Incident record.
2. WHEN Remediation Playbook 2 (Dangerous Security Group Change) is executed with a target security group ID and Incident ID, THE Playbook SHALL record the full definition of the offending inbound rule in the Forensic Evidence Package before removal, then remove the inbound rule permitting `0.0.0.0/0` or `::/0` access on port 22 (SSH) or port 3389 (RDP).
3. WHEN Remediation Playbook 3 (Public S3 Exposure) is executed with a target bucket name and Incident ID, THE Playbook SHALL record the previous public access configuration in the Forensic Evidence Package, then apply S3 Block Public Access with all four settings set to `true`, then verify within 30 seconds that `GetBucketPublicAccessBlock` returns all four settings as `true`.
4. WHEN Remediation Playbook 4 (Compromised EC2 Instance) is executed with a target instance ID and Incident ID, THE Playbook SHALL replace all security groups on the instance with the pre-existing Platform quarantine security group named `cloudsec-quarantine` that has no inbound or outbound rules, tag the instance with `SecurityStatus: QUARANTINED` and the Incident ID, and SHALL NOT terminate the instance.
5. WHEN Remediation Playbook 5 (CloudTrail Tampering) is executed with a target trail ARN and Incident ID, THE Playbook SHALL re-enable logging on the trail using `cloudtrail:StartLogging`, verify within 60 seconds that `GetTrail` returns `IsLogging: true`, apply an S3 bucket policy deny for `cloudtrail:DeleteTrail`, `cloudtrail:StopLogging`, and `cloudtrail:UpdateTrail` except for principals listed in the `CloudTrailProtectedPrincipals` Platform parameter, and record all configuration changes in the Forensic Evidence Package.
6. WHEN Remediation Playbook 6 (IAM Privilege Escalation) is executed with a target principal ARN, policy identifier, and Incident ID, THE Playbook SHALL record the full content of the offending policy statement in the Forensic Evidence Package before removal, then detach or delete the policy or inline policy statement that grants the escalated permission, and SHALL NOT delete the IAM principal.
7. EACH Remediation Playbook SHALL be implemented as an AWS Step Functions state machine with a unique name prefixed `cloudsec-remediation-`.
8. EACH Remediation Playbook SHALL be idempotent: executing the same Playbook twice for the same Incident SHALL result in the same resource protection state, defined as the target resource remaining in its post-remediation secure configuration, without returning an error on the second execution.
9. IF a Remediation Playbook step fails, THEN THE Playbook SHALL log the failure reason and step name to CloudWatch Logs, transition the Incident to `ESCALATED`, and SHALL NOT remove, overwrite, or modify data already written to the Forensic Evidence Package.
10. IF a Remediation Playbook is invoked with a missing or malformed required input parameter, THEN THE Playbook SHALL terminate immediately with a FAILED status and record the parameter validation error in CloudWatch Logs before performing any resource modification.
11. WHEN a Remediation Playbook execution completes, THE Platform SHALL record the complete Step Functions execution ARN and final execution status (`SUCCEEDED`, `FAILED`, or `TIMED_OUT`) in the Incident record.

---

### Requirement 11: Verification Engine

**User Story:** As a security engineer, I want the Platform to automatically verify that remediation actions succeeded, so that I can trust that an Incident marked RESOLVED has actually been contained.

#### Acceptance Criteria

1. WHEN a Remediation Playbook completes with a success status, THE Verification Engine SHALL begin verification within 60 seconds.
2. WHEN a Remediation Playbook completes with a success status, THE Verification Engine SHALL perform the playbook-specific verification checks listed below and complete all checks within 120 seconds of starting verification:
   - For Playbook 1: verify that the deny policy is attached to the principal and that no active sessions exist.
   - For Playbook 2: verify that no inbound rule permitting port 22 or 3389 from `0.0.0.0/0` or `::/0` exists in the security group.
   - For Playbook 3: verify that `GetBucketPublicAccessBlock` returns all four block settings as `true`.
   - For Playbook 4: verify that the instance's security group list contains only the quarantine security group ARN.
   - For Playbook 5: verify that `GetTrail` returns `IsLogging: true` for the affected trail.
   - For Playbook 6: verify that the escalated permission is no longer present in any attached or inline policy for the principal.
3. WHEN all verification checks pass, THE Verification Engine SHALL transition the Incident to status `RESOLVED` and set the `verification_timestamp` field in the Incident record.
4. IF any verification check fails, THEN THE Verification Engine SHALL transition the Incident to `ESCALATED`, record the identity of the failed check in the `failed_verification_check` field of the Incident record, and emit a `VerificationFailure` CloudWatch metric.
5. IF the Verification Engine cannot execute one or more verification checks due to an API error or timeout, THEN THE Verification Engine SHALL transition the Incident to `ESCALATED`, record the check that could not be executed and the reason in the `failed_verification_check` field of the Incident record, and emit a `VerificationFailure` CloudWatch metric.
6. WHEN the Incident transitions to `RESOLVED` or `ESCALATED`, THE Verification Engine SHALL re-query GuardDuty and Security Hub for Findings in an `ACTIVE` or `NEW` state related to the affected resource and record whether any such Findings remain in the Incident record.
7. WHEN the Incident transitions to `RESOLVED` or `ESCALATED`, THE Verification Engine SHALL record its complete check results, including the API responses used for each verification check, in the Forensic Evidence Package.

---

### Requirement 12: Forensic Evidence Preservation

**User Story:** As a security engineer, I want all artifacts from every Incident to be preserved in encrypted, tamper-evident storage, so that evidence is available for forensic analysis, compliance, and legal purposes.

#### Acceptance Criteria

1. WHEN an Incident is created, THE Platform SHALL create a Forensic Evidence Package in S3 for that Incident, stored at the path `s3://{forensic-bucket}/{incident_id}/`.
2. WHEN an artifact is generated during Incident processing, THE Platform SHALL write that artifact to the Forensic Evidence Package. The Package SHALL contain the following artifact types: all raw CloudTrail events associated with the Incident, all Finding JSON payloads, all resource configuration snapshots from AWS Config, all Investigation Reports produced, all raw Bedrock model responses (including failed attempts), all Remediation Playbook execution logs, all human approval records, all Verification Engine check results, and the final Incident Report.
3. THE Platform SHALL encrypt all objects in the forensic S3 bucket using an AWS KMS Customer Managed Key with key rotation enabled.
4. THE Platform SHALL enable S3 Object Versioning on the forensic S3 bucket.
5. THE Platform SHALL configure an S3 Object Lock retention policy of 365 days in COMPLIANCE mode on the forensic S3 bucket.
6. THE Platform SHALL apply an S3 bucket policy that denies `s3:DeleteObject`, `s3:DeleteObjectVersion`, and `s3:PutBucketPolicy` to all principals except the designated KMS key administrator role ARN defined as a Terraform variable.
7. THE Platform SHALL restrict read access to the forensic S3 bucket to the Security Account's `cloudsec-investigator` IAM role only.
8. WHEN an artifact is written to the Forensic Evidence Package, THE Platform SHALL record the S3 object key and ETag of that artifact in the Incident DynamoDB record within 10 seconds of the write completing.
9. THE Platform SHALL apply a lifecycle rule that transitions objects in the forensic S3 bucket to S3 Glacier after 90 days and expires objects after 2555 days (7 years).
10. IF an artifact write to the Forensic Evidence Package fails, THEN THE Platform SHALL emit a `ForensicWriteFailure` CloudWatch metric, log the failure with the Incident ID and artifact type, and SHALL NOT suppress the failure silently.

---

### Requirement 13: Incident Knowledge Base

**User Story:** As a security analyst, I want the Platform to store confirmed, resolved Incidents in a knowledge base, so that future AI Investigations can benefit from past experience without being contaminated by unverified data.

#### Acceptance Criteria

1. IF an Incident has reached status `RESOLVED` and the Verification Engine has recorded a `REMEDIATION_CONFIRMED` signal for that Incident, THEN THE Incident Knowledge Base SHALL store an entry for that Incident.
2. THE Incident Knowledge Base entry SHALL contain: Incident ID, severity, attack classification, MITRE ATT&CK mapping, affected resource types, root cause summary (maximum 500 characters), remediation playbook used, time-to-resolve in seconds, and confidence score at the time of resolution.
3. WHEN an AI Investigation begins for a new Incident, THE AI Investigation Engine SHALL query the Incident Knowledge Base for entries matching the current Incident's attack classification before invoking Amazon Bedrock.
4. IF the knowledge base query returns more than 3 matching entries, THE AI Investigation Engine SHALL select the 3 most recent entries by `resolved_timestamp` descending and include them as examples in the Bedrock prompt.
5. IF the knowledge base query returns zero matching entries, THE AI Investigation Engine SHALL invoke Amazon Bedrock without knowledge base examples.
6. IF an Incident has status `ESCALATED` or has a final confidence score strictly less than 0.70, THEN THE Incident Knowledge Base SHALL reject any attempt to store an entry for that Incident and SHALL record the rejection reason in CloudWatch Logs.
7. WHEN the AI Investigation Engine includes knowledge base entries in a Bedrock prompt, THE Platform SHALL replace all AWS account IDs, resource ARNs, and principal names in those entries with anonymized tokens before including them in the prompt.
8. THE Incident Knowledge Base SHALL be implemented as a DynamoDB table with a partition key of `attack_classification` and a sort key of `resolved_timestamp`.

---

### Requirement 14: AI-Generated Incident Report

**User Story:** As a security engineer and portfolio demonstrator, I want the Platform to produce a comprehensive, human-readable incident report, so that I can communicate the full Incident lifecycle to stakeholders.

#### Acceptance Criteria

1. WHEN an Incident transitions to status `RESOLVED` or `ESCALATED`, THE Reporting Engine SHALL generate a final Incident Report in both JSON and Markdown formats within 120 seconds of the status transition.
2. THE Incident Report SHALL contain the following sections: Incident ID and metadata, severity and confidence score, executive summary, chronological attack timeline, initial access assessment, root cause determination, affected identities, affected resources, blast radius summary, MITRE ATT&CK mapping table, evidence summary, automated actions taken, human-approved actions taken, verification result, remaining open risks, and recommended follow-up actions.
3. WHEN the Reporting Engine invokes Amazon Bedrock for narrative generation, THE Reporting Engine SHALL instruct the model to generate content for the following sections only: executive summary, attack timeline narrative, root cause narrative, and recommended follow-up actions.
4. WHEN a Bedrock-generated section is produced, THE Reporting Engine SHALL verify that the section does not contain any IAM principal ARNs, AWS account IDs, or resource ARNs that were not present in the Investigation Report evidence bundle.
5. IF the validation in criterion 4 detects unauthorized identifiers in a Bedrock-generated section, THEN THE Reporting Engine SHALL discard the Bedrock-generated content for that section and replace it with the structured data equivalent, marked with a `[NARRATIVE VALIDATION FAILED]` label.
6. IF the Bedrock invocation for narrative generation does not return a valid response within 30 seconds or returns an error, THEN THE Reporting Engine SHALL generate the Incident Report using only the structured data fields and SHALL mark the affected narrative sections as `[AI NARRATIVE UNAVAILABLE]`.
7. WHEN the Incident Report generation completes, THE Reporting Engine SHALL write both the JSON and Markdown versions to the Forensic Evidence Package and record the S3 object keys in the Incident DynamoDB record.
8. IF the S3 write in criterion 7 fails, THEN THE Reporting Engine SHALL emit a `ReportStorageFailure` CloudWatch metric, log the failure with the Incident ID, and update the Incident record with a `report_status` field set to `STORAGE_FAILED`.

---

### Requirement 15: Observability and Alerting

**User Story:** As a platform operator, I want comprehensive monitoring of the Platform's operational health, so that failures in the security pipeline are detected and addressed before they cause missed Incidents.

#### Acceptance Criteria

1. THE Platform SHALL publish the following custom CloudWatch metrics in the `CloudSecAI/Operations` namespace: `TelemetryIngestionLag`, `ParseFailure`, `CorrelationDecision`, `BedrockSchemaFailure`, `BedrockInvocationLatencyMs`, `RemediationDecision`, `VerificationFailure`, `IncidentOpenCount`, `IncidentMTTR` (mean time to resolve in seconds).
2. THE Platform SHALL create CloudWatch Alarms for: `BedrockSchemaFailure` count greater than 3 in a 5-minute period, `VerificationFailure` count greater than 1 in a 15-minute period, `TelemetryIngestionLag` greater than 900 seconds for any source, any Step Functions state machine entering FAILED state evaluated over a 1-minute period.
3. THE Platform SHALL route all CloudWatch Alarm state-change notifications to the SNS topic ARN provided as a Terraform variable named `notification_topic_arn`.
4. THE Platform SHALL emit structured JSON log entries from all Lambda functions, including: `incident_id`, `function_name`, `request_id`, `log_level` (one of DEBUG, INFO, WARN, or ERROR), `message`, and `duration_ms`.
5. THE Platform SHALL NOT include credentials, KMS key material, raw secret values, or complete CloudTrail event payloads in CloudWatch Logs.
6. THE Platform SHALL configure AWS Lambda function log group retention to 30 days.
7. THE Platform SHALL create an AWS Budgets alert scoped to resources tagged `Project: cloudsec-ai` that fires when the estimated monthly spend exceeds USD 75.
8. THE Platform SHALL create a CloudWatch Dashboard named `CloudSecAI-Operations` displaying: Incident counts by status, Bedrock invocation latency, Lambda error rates by function, Step Functions execution success/failure rates, and telemetry ingestion lag by source.

---

### Requirement 16: Security and IAM Design

**User Story:** As a security engineer, I want the Platform to operate on the principle of least privilege with explicit trust boundaries, so that a compromise of any Platform component does not grant lateral movement across the Platform or the monitored accounts.

#### Acceptance Criteria

1. THE Platform SHALL define a separate IAM execution role for each Lambda function; each role's policy SHALL contain no wildcard (`*`) actions and SHALL be scoped only to the specific AWS API actions that function requires.
2. THE Platform SHALL define a separate IAM execution role for each Step Functions state machine, scoped only to the specific Lambda functions it may invoke, the DynamoDB tables it may read or write, and any other resources it directly accesses.
3. WHEN a Lambda function requires a configuration secret, THE Lambda function SHALL retrieve the secret by ARN from AWS Secrets Manager at cold-start and SHALL NOT read secret values from environment variables; the only environment variable permitted to reference secrets is the variable holding the Secrets Manager ARN.
4. THE Platform SHALL define a cross-account IAM role in each Workload Account named `CloudSecAI-ReadRole` with read-only permissions for CloudTrail, GuardDuty, Security Hub, Config, EC2, IAM, and S3 metadata, and with a trust policy that explicitly lists the Security Account ID as the sole trusted principal.
5. THE Platform SHALL define a cross-account IAM role in each Workload Account named `CloudSecAI-RemediationRole` with permissions scoped to the specific API actions required by each Remediation Playbook, and with a trust policy restricted to the Security Account's Remediation Step Functions execution role ARN.
6. THE Platform SHALL NOT include the Bedrock service principal (`bedrock.amazonaws.com`) in any IAM role trust policy, and SHALL NOT grant any IAM role with Bedrock invocation permissions the ability to call non-Bedrock AWS service APIs.
7. THE AI Investigation Engine Lambda function SHALL pass only the assembled evidence bundle to the Bedrock `InvokeModel` API; it SHALL NOT pass unfiltered raw CloudTrail log objects to Bedrock.
8. ALL S3 buckets created by the Platform SHALL have `BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, and `RestrictPublicBuckets` set to `true`.
9. ALL DynamoDB tables created by the Platform SHALL have encryption at rest enabled using a Platform-managed AWS KMS CMK; each table SHALL use its own CMK.
10. THE Platform SHALL tag all AWS resources with: `Project: cloudsec-ai`, `Environment` (valid values: `dev`, `staging`, `prod`), `ManagedBy: terraform`, and `CriticalityTier` (valid values: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).

---

### Requirement 17: Multi-Account Architecture

**User Story:** As a cloud architect, I want the Platform to be designed for AWS Organizations multi-account deployment from the start, so that expanding from the MVP two-account layout to a full organization requires configuration changes only, not architectural rework.

#### Acceptance Criteria

1. THE Platform SHALL deploy all centralized infrastructure (EventBridge event bus, DynamoDB tables, S3 buckets, Step Functions, AI Investigation Engine, Safety Validation Engine, Verification Engine, Reporting Engine) exclusively in the Security Account.
2. THE Platform SHALL use AWS Config Aggregator with an Organizations-level data source to collect configuration data from all Workload Accounts without requiring per-account configuration.
3. THE Platform SHALL use an Organizations-level CloudTrail trail for management event collection, requiring a single trail configuration rather than per-account trails.
4. WHEN a new Workload Account is added to the AWS Organization, THE Platform SHALL require only the deployment of the `CloudSecAI-ReadRole` and `CloudSecAI-RemediationRole` IAM roles in that account, after which the Security Account SHALL be able to read Findings, CloudTrail events, and Config data from the new account within 24 hours.
5. THE Platform SHALL store the account ID and account type (valid values: `security`, `production`, `development`, `workload`) of each monitored Workload Account in a DynamoDB table named `cloudsec-account-inventory`, populated by a Lambda that queries `organizations:ListAccounts` on a 24-hour schedule.
6. IF the `ListAccounts` Lambda fails to complete successfully, THE Platform SHALL emit a `AccountInventoryUpdateFailure` CloudWatch metric and notify the configured SNS topic.
7. THE Platform SHALL include the source Workload Account ID in every Incident record, every Finding record, and every Forensic Evidence Package artifact.

---

### Requirement 18: Infrastructure as Code

**User Story:** As a developer, I want all Platform infrastructure defined in Terraform, so that the environment is reproducible, version-controlled, and deployable to multiple environments.

#### Acceptance Criteria

1. THE Platform SHALL define all AWS resources using Terraform configuration files organized into reusable modules under `terraform/modules/`.
2. THE Platform SHALL define separate Terraform root modules for each deployment environment under `terraform/environments/`, parameterized by environment name (`dev`, `staging`, `prod`).
3. THE Platform SHALL store Terraform state in an S3 backend with DynamoDB state locking, with the backend bucket and lock table deployed in the Security Account.
4. THE Platform SHALL pass `terraform validate` and `terraform plan -var-file=environments/{env}.tfvars` without errors when executed against a workspace where all required Terraform variables are provided and no prior state exists.
5. THE Platform SHALL not hard-code any AWS account IDs, region names, ARNs, or secret values in Terraform configuration files; all environment-specific values SHALL be provided through `.tfvars` files or AWS SSM Parameter Store data sources.
6. THE Platform's Terraform modules SHALL follow the directory structure: `terraform/modules/{module_name}/main.tf`, `variables.tf`, `outputs.tf`.

---

### Requirement 19: Testing

**User Story:** As a developer, I want a comprehensive test suite covering all Platform components, so that regressions are caught before deployment and security properties are continuously verified.

#### Acceptance Criteria

1. THE Platform SHALL include Python unit tests for all Lambda function handlers using `pytest`, achieving a minimum 80% line coverage for each Lambda function.
2. THE Platform SHALL include integration tests that verify the end-to-end flow from GuardDuty Finding ingestion through Incident creation and Correlation Engine assignment, using mocked AWS service responses via the `moto` library, where "end-to-end" is defined as starting at the EventBridge event and concluding with a DynamoDB Incident record in `OPEN` status.
3. THE Platform SHALL include a JSON Schema validation test suite that asserts valid Investigation Reports pass schema validation and invalid Investigation Reports (missing required fields, incorrect field types) fail schema validation.
4. THE Platform SHALL include idempotency tests for each Remediation Playbook that invoke the Playbook twice for the same Incident ID and the same target resource, and assert that the target resource is in the same protection state after both invocations.
5. THE Platform SHALL include negative tests that verify the Safety Validation Engine assigns Level 3 to actions not present in the Approved Action Policy.
6. THE Platform SHALL include Terraform validation tests using `terraform validate` and `tflint` in the CI pipeline.

---

### Requirement 20: Safe Attack Simulation

**User Story:** As a portfolio demonstrator, I want safe, scripted attack simulations for all six supported Incident scenarios, so that I can demonstrate the Platform's end-to-end detection and response capabilities in a controlled environment.

#### Acceptance Criteria

1. THE Platform SHALL include simulation scripts for each of the 6 Remediation Playbook scenarios: Compromised IAM Credential, Dangerous Security Group Change, Public S3 Exposure, Compromised EC2 Instance, CloudTrail Tampering, and IAM Privilege Escalation.
2. WHEN a simulation script is executed, THE script SHALL verify at startup that the current AWS account ID returned by `sts:GetCallerIdentity` matches the Lab Environment account ID defined in the script as a constant; IF the account IDs do not match, THEN THE script SHALL exit immediately with a non-zero status code and SHALL NOT perform any simulation actions.
3. WHEN a simulation completes, THE simulation script SHALL produce a simulation report documenting: the simulated attack steps performed, the expected Platform detection signal, the actual Incident ID created, and the remediation action taken.
4. THE simulation scripts SHALL be stored under `attack-simulations/` and SHALL NOT be executable in the Production or Security Account IAM role context.
5. WHEN a simulation cleanup script is executed, THE script SHALL restore the Lab Environment to its pre-simulation configuration, and WHEN cleanup completes, THE script SHALL verify that each modified resource has returned to its pre-simulation state before exiting with a zero status code.
