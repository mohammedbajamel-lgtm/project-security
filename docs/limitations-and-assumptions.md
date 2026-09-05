# Limitations and assumptions

## Known limitations

- Investigation quality depends on evidence completeness and model capability; hallucinations are mitigated, not eliminated.
- Cross-account correlation requires explicit trust and workload configuration.
- Useful behavior baselines generally require at least seven days of representative data.
- Six lab scenarios are implemented; they are not an exhaustive attack catalogue.
- Deployment is single-region and EventBridge is near-real-time, not sub-second streaming.
- Service quotas, regional Bedrock availability, and eventual consistency can delay workflows.

## MVP versus production

| Area | MVP/lab | Production expectation |
|---|---|---|
| Accounts | one workload or isolated namespace | multiple workload accounts through Organizations |
| Baselines | manually seeded/short history | automated 30-day import and tuning |
| Approval | single approver workflow | multiple approvers, RBAC, break-glass review |
| Evidence | 30-day dev retention | 365 days plus Glacier/legal retention |
| API edge | Cognito/API Gateway | WAF, rate limits, private access where possible |
| Keys | regional dev CMKs | backed-up key strategy; multi-region if required |

## Security assumptions

- API Gateway enforces TLS; Cognito uses MFA and secure client configuration.
- KMS administrators and keys are not compromised.
- CloudTrail remains enabled and tamper-evident in every participating account.
- EventBridge routing and the Safety Validation Engine are protected by change control.
- Human approvers are trustworthy and their identities are not compromised.

If any assumption fails, automated action should be disabled and incidents handled manually until trust is restored.
