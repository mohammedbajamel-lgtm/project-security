# Terraform Backend Configuration

This directory contains the Terraform backend infrastructure (S3 bucket +
DynamoDB state lock table). Deployed in the Security Account.

## Required Backend Block

Add the following to your Terraform configuration:

```hcl
terraform {
  backend "s3" {
    bucket         = "cloudsec-{env}-{account}-terraform-state-{unique-id}"
    key            = "cloudsec-{env}/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "cloudsec-{env}-terraform-locks"
  }
}
```

## Properties

| Property               | Value                        |
|------------------------|------------------------------|
| Versioning             | Enabled                      |
| Block public access    | true (all four settings)     |
| Encryption             | SSE-KMS with customer key    |
| DynamoDB WCU / RCU     | 5 / 5                        |
| DynamoDB partition key | LockID (String)              |