# Threat model

## Trust boundaries and assets

External attackers and Workload Accounts are untrusted inputs. The Security Account is the control plane. Lab/Demo is disposable and isolated from production. AWS managed services and Bedrock are external service boundaries; model output is untrusted. See [architecture](architecture.md).

Protected assets include findings, incidents, baselines, approval decisions, audit records, knowledge items, evidence objects, KMS keys, Terraform state, credentials, and execution roles.

## STRIDE analysis and controls

| Category | Representative threats | Primary controls | Residual risk |
|---|---|---|---|
| Spoofing | forged findings/principal ARNs; approval API impersonation | source rules, schema checks, evidence cross-reference, Cognito/MFA, request identity audit | compromised trusted identity |
| Tampering | DynamoDB edits; evidence or bucket-policy changes | conditional writes, KMS, versioning/object retention, CloudTrail, least privilege | privileged control-plane compromise |
| Repudiation | denied action or deleted audit trail | CloudTrail, immutable evidence versions, decision and workflow IDs | log service/account compromise |
| Information disclosure | finding/prompt leakage; cross-account exposure | redaction, scoped roles/key policies, encryption, no secrets in logs | model/provider metadata exposure |
| Denial of service | Lambda/DynamoDB/Bedrock throttling; backlog | retries, DLQ, alarms, quotas, bounded payloads and concurrency | regional outage or quota exhaustion |
| Elevation of privilege | role chaining; manipulated model output; safety bypass | permission boundaries, action allow-list, deterministic safety engine, approval, independent verification | deployment-admin compromise |

## Prompt-injection path

An attacker can place instructions in resource names, CloudTrail parameters, tags, or finding text. These values are data, never system instructions. The platform redacts input, labels evidence, constrains the prompt, requires strict JSON, validates citations and entities against the package, applies an action allow-list, and treats model output as untrusted. A failed control rejects or escalates; Bedrock cannot call AWS APIs.

## Residual risks

The design accepts bounded model error, eventual consistency, regional dependency, administrator compromise risk, and incomplete attack coverage. Production use additionally requires organizational SCPs, WAF/rate limiting, multi-person approval, security testing, incident runbooks, backup/restore exercises, and continuous policy review.
