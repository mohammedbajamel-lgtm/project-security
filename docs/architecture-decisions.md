# Architecture decision records

Each record uses Context, Alternatives, Decision, Trade-offs, and Consequences.

## ADR-001 — Serverless compute

**Context:** bursty security events need isolation and low idle cost. **Alternatives:** EC2 services or EKS. **Decision:** Lambda and Step Functions. **Trade-offs:** runtime limits, cold starts, quotas, and distributed tracing. **Consequences:** smaller patching surface, per-use scaling, and explicit workflow state.

## ADR-002 — EventBridge security bus

**Context:** several event types need filtered fan-out. **Alternatives:** point-to-point SQS or SNS. **Decision:** a dedicated custom EventBridge bus, with SQS retained for dead letters. **Trade-offs:** EventBridge quotas and eventual delivery. **Consequences:** producers and consumers remain decoupled and routing policy is auditable.

## ADR-003 — DynamoDB data stores

**Context:** incident entities are keyed, document-oriented, and bursty. **Alternatives:** RDS or self-managed databases. **Decision:** purpose-built DynamoDB tables. **Trade-offs:** access patterns must be designed upfront. **Consequences:** no database host, automatic scaling, conditional writes, and straightforward encryption.

## ADR-004 — Managed Bedrock models

**Context:** investigations benefit from language reasoning without model hosting. **Alternatives:** self-hosted models or no AI. **Decision:** Bedrock behind a deterministic evidence and safety boundary. **Trade-offs:** variable model quality, availability, latency, and token cost. **Consequences:** managed infrastructure while execution authority stays outside the model.

## ADR-005 — Versioned S3 evidence

**Context:** forensic artifacts must resist accidental alteration. **Alternatives:** EBS snapshots or database blobs. **Decision:** versioned, KMS-encrypted S3 with retention/object-lock controls where enabled. **Trade-offs:** retention can delay deletion and increase storage. **Consequences:** durable manifests and independently verifiable object versions.

## ADR-006 — Customer-managed KMS keys

**Context:** findings, incidents, evidence, and parameters have different access needs. **Alternatives:** AWS-managed keys. **Decision:** separate rotating CMKs. **Trade-offs:** fixed monthly cost and policy complexity. **Consequences:** scoped grants, revocation control, and key-specific audit history.

## ADR-007 — Step Functions orchestration

**Context:** remediation needs retries, waits, approval callbacks, rollback and auditability. **Alternatives:** Lambda chaining or queues plus custom state. **Decision:** Step Functions. **Trade-offs:** workflow complexity and transition costs. **Consequences:** visible durable execution with explicit failure paths.

## ADR-008 — API Gateway and Cognito approval

**Context:** decisions must be authenticated and auditable. **Alternatives:** CLI scripts, email links, or direct table edits. **Decision:** API Gateway with Cognito and a decision Lambda. **Trade-offs:** identity configuration and API cost. **Consequences:** accessible, attributable approvals with self-approval prevention.
