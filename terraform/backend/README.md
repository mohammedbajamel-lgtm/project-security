# Terraform Backend - Bootstrap & Configuration

This directory contains the **bootstrap** Terraform configuration that creates
the S3 bucket used as the remote backend for the main platform infrastructure.

## Why Bootstrap?

Terraform remote state has a chicken-and-egg problem: you need the backend
resource (S3 bucket) to exist **before** you can use it as a backend. The
bootstrap configuration solves this by using the **local backend** to create
the bucket, then the main platform configuration switches to the remote
backend.

## Architecture

```
terraform/backend/              <- Bootstrap (local backend, applied first)
  main.tf                       <- Creates S3 bucket + security policy + encryption + versioning
  variables.tf                  <- Environment/cost-center inputs

terraform/environments/*/       <- Main platform (remote backend, applied second)
  backend.hcl                   <- Points at the bootstrap-created bucket
```

## Two-Stage Bootstrap Design (resolves T01-02 ↔ T01-07 dependency cycle)

There is an inherent dependency cycle between "create the Terraform backend
bucket" (T01-02) and "create the IAM role that manages Terraform state"
(T01-07). Each needs the other to exist first. This bootstrap design
**breaks that cycle into two reviewed stages** so that no placeholder or
nonexistent role ARN is ever written into a bucket policy:

### Stage 1 — T01-02 (this file)

Creates the S3 bucket with full security guardrails using only the
authenticated bootstrap operator's existing IAM permissions. Stage 1
contains **no role-scoped Allow statements** because the deploy role does
not yet exist. The bucket policy in Stage 1 contains only security `Deny`
statements:

| Control | Value |
|---------|-------|
| S3 bucket name | `cloudsec-{env}-{account}-state-{12-hex-chars}` (auto-unique) |
| Account / region source | Authenticated AWS identity (`aws_caller_identity.current`) |
| Versioning | Enabled |
| Block public access | true (all four settings) |
| Encryption | SSE-S3 (AES256) — upgrade to SSE-KMS after T01-06 |
| force_destroy | false (never auto-delete state) |
| Bucket policy | Two `Deny` statements only: insecure-transport, unencrypted-uploads |
| State object deletion guard | NOT applied in Stage 1 (no role principal exists yet) |

The authenticated bootstrap operator performs the initial `terraform apply`
using their own existing IAM permissions. The `Deny` statements are guarded
by conditions (insecure transport, unencrypted uploads) so they do not
block legitimate operational access by the bootstrap operator or the bucket
owner (root account).

### Stage 2 — post-T01-07 (separate reviewed plan)

After the Terraform deployment role is created in T01-07, a **separate
Terraform plan** adds the role-scoped `Allow` statements to the bucket
policy. This Stage-2 change is reviewed before apply. The expected Stage-2
bucket policy is:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid":    "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action":   "s3:*",
      "Resource": [
        "arn:aws:s3:::cloudsec-{env}-{account}-state-{suffix}",
        "arn:aws:s3:::cloudsec-{env}-{account}-state-{suffix}/*"
      ],
      "Condition": { "Bool": { "aws:SecureTransport": "false" } }
    },
    {
      "Sid":    "DenyUnencryptedUploads",
      "Effect": "Deny",
      "Principal": "*",
      "Action":   "s3:PutObject",
      "Resource": "arn:aws:s3:::cloudsec-{env}-{account}-state-{suffix}/*",
      "Condition": {
        "StringNotEquals": { "s3:x-amz-server-side-encryption": "AES256" }
      }
    },
    {
      "Sid":    "DenyStateObjectDeletion",
      "Effect": "Deny",
      "Principal": { "AWS": "arn:aws:iam::<account>:role/<terraform-deploy-role>" },
      "Action":   "s3:DeleteObject",
      "Resource": "arn:aws:s3:::cloudsec-{env}-{account}-state-{suffix}/cloudsec-{env}/terraform.tfstate"
    },
    {
      "Sid":    "AllowListBucketForStateDiscovery",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::<account>:role/<terraform-deploy-role>" },
      "Action":   "s3:ListBucket",
      "Resource": "arn:aws:s3:::cloudsec-{env}-{account}-state-{suffix}",
      "Condition": {
        "StringEquals": { "s3:prefix": "cloudsec-{env}/" }
      }
    },
    {
      "Sid":    "AllowStateObjectReadWrite",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::<account>:role/<terraform-deploy-role>" },
      "Action":   [ "s3:GetObject", "s3:PutObject" ],
      "Resource": "arn:aws:s3:::cloudsec-{env}-{account}-state-{suffix}/cloudsec-{env}/terraform.tfstate"
    },
    {
      "Sid":    "AllowStateLockFileReadWrite",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::<account>:role/<terraform-deploy-role>" },
      "Action":   [ "s3:GetObject", "s3:PutObject", "s3:DeleteObject" ],
      "Resource": "arn:aws:s3:::cloudsec-{env}-{account}-state-{suffix}/cloudsec-{env}/terraform.tfstate.tflock"
    }
  ]
}
```

**Key properties of the Stage-2 backend role permissions:**

| Permission | Scope | Key |
|------------|-------|-----|
| `s3:ListBucket` | Bucket ARN | Condition `s3:prefix = "cloudsec-{env}/"` |
| `s3:GetObject` | State file | `cloudsec-{env}/terraform.tfstate` |
| `s3:PutObject` | State file | `cloudsec-{env}/terraform.tfstate` |
| `s3:GetObject` | Lock file | `cloudsec-{env}/terraform.tfstate.tflock` |
| `s3:PutObject` | Lock file | `cloudsec-{env}/terraform.tfstate.tflock` |
| `s3:DeleteObject` | Lock file | `cloudsec-{env}/terraform.tfstate.tflock` |

**`s3:DeleteObject` is granted on the `.tflock` file, NOT on
`terraform.tfstate`.** Accidental state-file deletion remains blocked by
the explicit `DenyStateObjectDeletion` statement.

## State Locking — `use_lockfile` vs `.terraform.lock.hcl`

These are two unrelated mechanisms. Confusing them causes real operational
errors.

### `use_lockfile = true` — S3 state locking

This is the S3 backend setting that enables Terraform's distributed state
lock. When `use_lockfile = true` is set in the `backend "s3"` block,
Terraform writes a small object at
`<state_key>.tflock` (e.g. `cloudsec-dev/terraform.tfstate.tflock`)
alongside the state file to prevent concurrent writers. This is what the
Stage-2 bucket policy grants `s3:GetObject`/`s3:PutObject`/`s3:DeleteObject`
for. The `.tflock` object is transient — Terraform deletes it when the
operation completes.

### `.terraform.lock.hcl` — provider version pin file

This is an entirely separate file that Terraform writes in the **local
working directory** to record which provider versions it resolved during
`terraform init`. It has nothing to do with state locking. It **must be
committed to Git** so that every developer and every CI runner resolves the
same provider versions. It should NOT appear in `.gitignore`.

## Bootstrap Workflow (Stage 1)

### 1. Apply Stage 1 bootstrap (creates S3 bucket with guardrails only)

```bash
cd terraform/backend

# First-time initialization (local backend - no remote state)
terraform init

# Review the plan
terraform plan -var-file=../environments/dev/dev.tfvars

# Apply - creates S3 bucket + guardrail policy + encryption + versioning
terraform apply -var-file=../environments/dev/dev.tfvars
```

### 2. Capture the outputs

```bash
terraform output state_bucket_name
terraform output state_bucket_arn
terraform output backend_config   # copy-paste block for step 3
terraform output state_lock_file_key   # for Stage-2 policy planning
```

### 3. Configure the main platform backend

Create `terraform/environments/<env>/backend.hcl` with the copy-paste
block from step 2. **Critical:** keep `use_lockfile = true` and do NOT
add a `dynamodb_table` setting unless explicitly required.

### 4. Initialize the main platform with the remote backend

```bash
cd terraform
terraform init -backend-config=environments/dev/backend.hcl
```

### 5. Stage 2 — apply role-scoped access (post-T01-07)

After T01-07 provisions the Terraform deployment role, copy
`dev.tfvars.example` to the ignored `dev.tfvars`, replace the example account
ID with the real role ARN, and run:

```bash
terraform plan -var-file=dev.tfvars -out=stage2-backend.tfplan
terraform show stage2-backend.tfplan
terraform apply stage2-backend.tfplan
```

The reviewed plan must update only `aws_s3_bucket_policy.terraform_state`.
It must not replace the bucket or change versioning, encryption, or public
access settings. The role ARN variable rejects IAM user ARNs.

## Resource Properties (Stage 1)

| Property | Value |
|----------|-------|
| S3 bucket name | `cloudsec-{env}-{account}-state-{12-hex-chars}` (auto-unique) |
| Account / region source | Authenticated AWS identity (`aws_caller_identity`) |
| S3 Versioning | Enabled |
| Block public access | true (all four settings) |
| Encryption | SSE-S3 (AES256) — upgrade to SSE-KMS after T01-06 |
| force_destroy | false (never auto-delete state) |
| State locking | S3 local lock file (`use_lockfile = true`), no DynamoDB |
| Bucket policy (Stage 1) | 2 Deny statements only: insecure-transport, unencrypted-uploads |
| Bucket policy (Stage 2) | +3 Deny (state deletion) + 3 Allow (role-scoped) per template above |
| Deploy role ARN | NOT used in Stage 1. Validated in Stage 2. |
| Admin recovery path | Preserved via bucket ownership (root account retains full access) |

## Security Notes

- **No placeholder role ARN.** Stage 1 never writes a nonexistent role
  ARN into a bucket policy. That would create a misleading authorization
  record and a false sense of security.
- **No Deny-all-except-one-role.** Stage-2 Allow statements are narrowly
  scoped (state key + `.tflock` key only). The bucket owner retains full
  access via bucket ownership — the administrative recovery path.
- **State-object deletion is denied to the deploy role** in Stage 2. The
  state file is never deletable by automation; recovery comes from a prior
  S3 version or an IaC snapshot.
- **`.tflock` is deletable by the deploy role.** This is required:
  Terraform must be able to acquire and release the state lock.
- **SSE-S3** is the T01-02 minimum. After T01-06 deploys customer-managed
  KMS keys, upgrade to SSE-KMS by modifying `sse_algorithm` to
  `"aws:kms"` and adding `kms_master_key_id`.
- **force_destroy = false** in every environment. Accidental deletion
  would destroy the Terraform source-of-truth. Deletion requires an
  explicit manual action outside Terraform.

## Cost

Approximately **$0.01/month** at idle in us-east-1 (S3 Standard storage
for a small Terraform state file).

| Component | Calculation | Monthly |
|-----------|-------------|---------|
| S3 Standard storage | < 10 MB x $0.023/GB x 2 (versioned copies) | < $0.01 |
| **Total** | | **~$0.01** |

No DynamoDB charges. No KMS charges (SSE-S3 included in S3 storage).

Pricing source: [AWS S3 Pricing](https://aws.amazon.com/s3/pricing/).

---

## Stage 1 Apply Record (dev)

| Field | Value |
|-------|-------|
| Applied | 2026-09-03 |
| Authenticated principal | `arn:aws:iam::000000000000:role/example-terraform-principal` |
| Account | `000000000000` |
| Region | `us-east-1` |
| Bucket name | `cloudsec-dev-000000000000-state-example123456` |
| Bucket ARN | `arn:aws:s3:::cloudsec-dev-000000000000-state-example123456` |
| State key | `cloudsec-dev/terraform.tfstate` |
| Lock file key | `cloudsec-dev/terraform.tfstate.tflock` |
| Versioning | Enabled |
| Default SSE | AES256 |
| Block public access | all four flags = true |
| Bucket policy | 2 Deny statements (insecure-transport, unencrypted-uploads), 0 Allow |
| force_destroy | false |
| Tags | Project=cloudsec-ai, Environment=dev, ManagedBy=terraform, CostCenter=security, Name=cloudsec-dev-terraform-state |
| Plan result | 6 added, 0 changed, 0 destroyed |

**Post-apply verification:** All nine checks passed independently against the live
AWS resources via AWS CLI (bucket existence, versioning, SSE, BPA, bucket policy
shape and Sids, single bucket in account, tags, empty object list, state file).

### Bootstrap State Preservation

The bootstrap Terraform runs with the **local** backend (no remote state). After
apply, Terraform stores state at:

```
terraform/backend/terraform.tfstate
```

This local state is the source of truth for the bootstrap resources until the
main platform switches to the remote backend. It has been backed up to:

```
terraform/backend/state-backups/terraform.tfstate.LATEST.backup
terraform/backend/state-backups/terraform.tfstate.<timestamp>.backup
```

**Rules for the bootstrap state:**

- Keep the state file and backups in `terraform/backend/state-backups/`.
- The bootstrap state should remain local-only. Do NOT commit it to Git (it is
  in `.gitignore`).
- After the main platform is initialized against the remote backend, the
  bootstrap resources remain managed here. To migrate the bootstrap state to
  the remote backend later, use `terraform init -migrate-state` with the
  backend config from `terraform/environments/dev/backend.hcl` — this is an
  optional cleanup step and can be done safely after the main platform is
  running, because the bootstrap state contains only the bucket itself (no
  application resources).
- Before any destructive bootstrap operation (`terraform destroy`), restore from
  the timestamped backup and confirm via AWS CLI.

### Stage 2 Trigger

Once the Terraform deployment role exists (T01-07), prepare the Stage-2
bucket-policy plan (adds role-scoped Allow statements + DenyStateObjectDeletion
on `terraform.tfstate` only). Do NOT apply Stage 2 without explicit approval;
review the plan first.

### Actual Copy-Paste Backend Block (dev, post-Stage-1)

```hcl
terraform {
  backend "s3" {
    bucket       = "cloudsec-dev-000000000000-state-example123456"
    key          = "cloudsec-dev/terraform.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
  }
}
```

This is mirrored in `terraform/environments/dev/backend.hcl` for use with
`terraform init -backend-config=...`.
