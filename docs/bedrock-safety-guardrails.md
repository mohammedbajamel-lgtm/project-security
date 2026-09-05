# Bedrock safety guardrails

## Principle: AI never executes

Bedrock receives a bounded, redacted evidence package and returns recommendations. It has no remediation IAM role and no direct AWS action path. A deterministic safety engine is the sole execution gate.

```text
Evidence → redaction → prompt → Bedrock recommendation
                              ↓
JSON schema → citation check → hallucination/evidence check → approved-action policy
→ risk classification → Level 3 reject | Level 2 human approval | Level 1 workflow
→ Step Functions → scoped playbook → independent verification → evidence/report
```

## Layered controls

1. **Strict JSON schema:** malformed or extra output is rejected and escalated.
2. **Evidence citations:** conclusions must cite evidence IDs present in the package.
3. **Hallucination detection:** principals, resources, and parameters are cross-checked with evidence.
4. **Approved Action Policy:** unknown or disallowed actions become Level 3 and cannot execute.
5. **Evidence validation:** action parameters must be traceable to accepted investigation facts.
6. **Risk classification:** blast radius, critical targets, confidence, and nighttime operation can only increase scrutiny; precedence is Level 3, then Level 2, then Level 1.
7. **Human approval:** Level 2 waits for an authenticated decision; expiry or rejection escalates safely. Self-approval is denied.
8. **Redaction:** credentials, personal data, tokens, account identifiers, and sensitive payloads are removed or masked before model use and knowledge storage.
9. **Prompt constraints:** the model is told to return schema-bound analysis, cite facts, avoid code execution, and never propose destructive or unapproved actions.

## Failure behavior

Schema, citation, evidence, policy, or hallucination failure rejects the recommendation. Low confidence and elevated risk require human review. Bedrock timeout retries within bounds, then escalates. Approval expiry/rejection makes no AWS change. Remediation failure invokes rollback where supported and escalates. Verification failure never reports success; it preserves evidence and escalates.
