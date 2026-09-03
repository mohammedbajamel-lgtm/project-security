---
inclusion: always
---

# CloudSec AI — Product Summary

CloudSec AI is an AWS-native, serverless automated incident response platform. It automates the full lifecycle: **Detect → Correlate → Investigate → Blast Radius → Safety Validate → Remediate → Verify → Report**.

## What it does

- Ingests security signals from GuardDuty, Security Hub, CloudTrail, VPC Flow Logs, AWS Config, and Amazon Security Lake.
- Correlates findings into incidents using principal, IP, and resource grouping rules with time windows.
- Uses Amazon Bedrock (Claude 3.5 Sonnet) to investigate incidents, reconstruct attack timelines, map to MITRE ATT&CK, and calculate blast radius.
- Routes every AI recommendation through a **deterministic Safety Validation Engine** — the AI never directly calls AWS APIs.
- Executes approved remediations via versioned Step Functions playbooks (6 scenarios: IAM credential compromise, dangerous SG change, public S3 exposure, compromised EC2, CloudTrail tampering, IAM privilege escalation).
- Verifies remediation success and either resolves or escalates the incident.
- Generates AI-assisted forensic incident reports (JSON + Markdown).
- Stores all evidence in an immutable, encrypted S3 bucket with Object Lock.

## Key design principles

1. **AI advises, determinism decides.** Bedrock output is always validated against a JSON Schema and cross-checked against the evidence bundle before any action.
2. **Forensic integrity first.** All evidence is encrypted (KMS CMK), versioned, and tamper-evident (S3 Object Lock in prod).
3. **Least privilege everywhere.** Every Lambda and Step Functions role contains only the specific API actions it requires. No wildcard `*` actions.
4. **Multi-account by design.** Security Account hosts all platform infra; Workload Accounts expose scoped read and remediation cross-account roles.
5. **Observable by default.** Every transition emits structured CloudWatch metrics and JSON logs.

## MVP scope

The MVP targets a two-account layout (Security Account + one Workload Account) in a single region, demonstrating one complete attack lifecycle (Compromised IAM Credential) end-to-end. The architecture supports transparent expansion to full AWS Organizations without code changes.

## Non-goals

- Real-time (sub-second) streaming — near-real-time via EventBridge.
- Multi-region deployment (requires additional configuration).
- Direct AI-to-AWS execution (explicitly forbidden by design).
