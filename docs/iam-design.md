# IAM and security design

```text
AWS SSO/deployer → Terraform deployment role
Workload telemetry services → Security Account ingestion role/bus
EventBridge → individual Lambda execution roles
Step Functions role → approval handler + remediation framework only
Remediation role → allow-listed target APIs on scoped resources
Verification role → read-only re-query APIs
Reporting/evidence roles → designated tables/buckets/topics and keys
```

## Permission matrix

| Principal | Allowed actions | Resource scope / reason |
|---|---|---|
| ingestion | put/query findings, publish normalized events, logs | finding table/key, security bus, own logs |
| correlation | query findings, update incidents, publish | findings/incidents and bus only |
| investigation | read incident evidence, invoke configured Bedrock model | named tables/model and own logs |
| safety-validation | read policy, write decisions, publish decisions | policy object/parameter, decision table, bus |
| Step Functions | invoke approval/remediation Lambdas | exact function ARNs |
| remediation | approved IAM/S3/EC2/SG/CloudTrail actions | lab/workload targets constrained by policy/tags |
| verification | read current resource/finding state | read-only target APIs |
| evidence/reporting | write evidence/reports; publish result | named encrypted buckets/topics |
| recovery | bounded rollback actions | recorded target resources only |
| security-admin/deployer | reviewed infrastructure administration | trusted principals, boundary and change control |

Lambda roles trust only `lambda.amazonaws.com`; workflow roles trust only their AWS service. EventBridge targets use resource policies and exact source ARNs where supported. Workload accounts can submit telemetry through explicitly configured cross-account roles/rules but cannot read Security Account stores.

Each data class has a CMK. Key policies retain account recovery authority and grant only the named service roles that need encrypt/decrypt/data-key operations. S3 policies deny insecure transport and unencrypted writes, then grant exact prefixes to evidence/report roles. EventBridge rules can invoke only their declared targets; failed delivery goes to the encrypted DLQ.

Cognito authenticates approvers; groups map to approval permissions, MFA is expected, identity is recorded, and the requester cannot approve their own decision. No application role receives `AdministratorAccess`. Broad metadata/list calls that cannot be resource-scoped are accepted only where AWS requires `Resource: *`, with action and role scope minimized and documented in Terraform review.
