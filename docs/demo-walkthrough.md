# 35-minute demo walkthrough

| Step | Time | Show and say |
|---:|---:|---|
| 1 | 2m | Problem: finding volume overwhelms manual triage. |
| 2 | 3m | Architecture and three trust boundaries. |
| 3 | 2m | Security versus workload/demo separation. |
| 4 | 2m | Run the credential-compromise demo wrapper. |
| 5 | 2m | Synthetic GuardDuty/CloudTrail telemetry. |
| 6 | 2m | EventBridge normalization and incident record. |
| 7 | 3m | Evidence-cited Bedrock investigation. |
| 8 | 2m | Ordered attack timeline and MITRE mapping. |
| 9 | 2m | Blast-radius output. |
| 10 | 1m | Confidence and risk classification. |
| 11 | 2m | Deterministic safety decision. |
| 12 | 2m | Step Functions remediation. |
| 13 | 2m | Approve one Level 2 case and explain rejection/expiry. |
| 14 | 2m | Independent state verification. |
| 15 | 1m | Evidence manifest/versioning. |
| 16 | 2m | JSON, Markdown and executive report. |
| 17 | 3m | Production scaling: Organizations, RBAC, retention and operations. |

Speaker theme: “AI recommends; policy decides; workflows execute; verification proves.” Do not show real identifiers. Reference screenshots from `docs/screenshots/` as fallbacks.

Common questions: model hallucinations are contained by evidence/schema/policy checks; Bedrock outage escalates without action; failed verification never resolves; cross-account access is explicit and one-way; cost is volume/model dependent.

Troubleshooting: if no incident appears, pause and inspect the bus/DLQ; if approval is unavailable, use the prepared screenshot rather than bypassing it; if AWS is degraded, use the recorded Phase 19 JSON. Never loosen IAM or safety policy during a presentation.
