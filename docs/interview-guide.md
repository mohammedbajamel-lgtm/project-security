# Interview guide

## 30-second pitch

CloudSec AI is a serverless AWS incident-response platform that turns noisy security findings into evidence-backed investigations and safely orchestrated remediation. Bedrock can recommend but cannot execute: deterministic schema, citation, evidence, policy and risk gates decide whether an action is rejected, sent to a human, or run through Step Functions and independently verified.

## Longer narrative

Manual response does not scale across accounts and tools. The 20-phase system separates telemetry, incident state, AI analysis, safety policy, execution, verification and evidence. EventBridge decouples stages, DynamoDB stores operational state, Bedrock performs bounded analysis, Step Functions makes workflow state visible, and KMS/S3 preserve evidence.

Key decisions: managed Bedrock avoids model hosting; Step Functions handles retries/approval/rollback; the Safety Validation Engine is separate so model output remains untrusted. Security comes from no AI-to-AWS path, allow-listed playbooks, scoped roles, human review for elevated risk, independent verification and tamper-evident records.

Production readiness requires Organizations integration, WAF/rate limits, multi-approver RBAC, longer archival, SLO/on-call ownership, penetration testing and disaster recovery. Costs vary; value comes from consistent triage and reduced engineer time, not an unverified fixed ROI claim.

## Technical Q&A

1. **Hallucinated action?** Unknown or unsupported actions fail schema/evidence/policy gates and cannot execute.
2. **Safety engine compromised?** Disable automation, revoke workflow permissions, preserve logs, and use organizational controls; it is a critical trust anchor.
3. **Cross-account incidents?** Explicit workload roles/rules submit telemetry to the Security Account; access is scoped and labeled.
4. **MTTD/MTTR?** Measure from event timestamps and workflow audit data; do not promise a number without production observations.
5. **Verification?** A separate role re-queries AWS and resolves only on confirmed state.
6. **Bedrock outage?** Bounded retries then escalation; no remediation is inferred.
7. **Prevent worse remediation?** allow-list, evidence binding, blast-radius escalation, approval, scoped APIs, rollback, verification.
8. **Duplicate events?** deterministic keys and conditional writes provide idempotency.
9. **Evidence integrity?** KMS, versioned/retained S3 objects, manifests, CloudTrail and scoped writers.
10. **Why DynamoDB?** predictable keyed access, burst scaling and no database host; joins/ad-hoc analytics are a trade-off.
11. **Why EventBridge plus SQS?** EventBridge routes/filter/fans out; SQS is the failure buffer.
12. **Prompt injection?** telemetry is untrusted data, redacted and schema/evidence validated; the model has no execution role.

For non-technical audiences: it is a guarded security assistant—like a responder who drafts a recommendation, while policy and an authorized person control risky changes.

Do not say the AI is autonomous, infallible, production-ready by default, zero-cost, or guaranteed to stop every attack. Point to [limitations](limitations-and-assumptions.md) and the [demo](demo-walkthrough.md).
