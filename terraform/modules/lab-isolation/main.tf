resource "random_id" "suffix" { byte_length = 4 }

locals {
  prefix       = "cloudsec-lab"
  trail_bucket = "${local.prefix}-${var.account_id}-trail-${random_id.suffix.hex}"
}

resource "aws_vpc" "lab" {
  cidr_block           = "10.250.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = merge(var.tags, { Name = "${local.prefix}-vpc" })
}

resource "aws_subnet" "lab" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = "10.250.1.0/24"
  map_public_ip_on_launch = false
  availability_zone       = "${var.region}a"
  tags                    = merge(var.tags, { Name = "${local.prefix}-isolated-subnet" })
}

resource "aws_s3_bucket" "trail" {
  bucket        = local.trail_bucket
  force_destroy = true
  tags          = merge(var.tags, { Name = "${local.prefix}-trail" })
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

data "aws_iam_policy_document" "trail" {
  statement {
    sid = "CloudTrailAclCheck"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.region}:${var.account_id}:trail/${local.prefix}-trail"]
    }
  }
  statement {
    sid = "CloudTrailWrite"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail.arn}/AWSLogs/${var.account_id}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.region}:${var.account_id}:trail/${local.prefix}-trail"]
    }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = data.aws_iam_policy_document.trail.json
}

resource "aws_cloudtrail" "lab" {
  name                          = "${local.prefix}-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_logging                = true
  depends_on                    = [aws_s3_bucket_policy.trail]
  tags                          = var.tags
}

resource "aws_guardduty_detector" "lab" {
  enable = true
  tags   = var.tags
}

resource "aws_securityhub_account" "lab" {
  enable_default_standards = false
}

data "aws_iam_policy_document" "boundary" {
  statement {
    sid       = "LabResourceOperations"
    effect    = "Allow"
    actions   = ["ec2:*", "s3:*", "iam:*", "cloudtrail:*", "securityhub:*", "guardduty:*", "logs:*", "cloudwatch:*"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/Environment"
      values   = ["lab"]
    }
  }
  statement {
    sid       = "LabTaggedCreation"
    effect    = "Allow"
    actions   = ["ec2:CreateTags", "ec2:RunInstances", "s3:CreateBucket", "iam:CreateUser", "iam:CreateRole", "cloudtrail:CreateTrail"]
    resources = ["*"]
    condition {
      test     = "StringEqualsIfExists"
      variable = "aws:RequestTag/Environment"
      values   = ["lab"]
    }
  }
  statement {
    sid       = "ReadForValidation"
    effect    = "Allow"
    actions   = ["sts:GetCallerIdentity", "ec2:Describe*", "s3:ListAllMyBuckets", "iam:Get*", "iam:List*", "cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus", "guardduty:List*", "guardduty:Get*", "securityhub:DescribeHub", "securityhub:GetFindings", "logs:Describe*", "cloudwatch:GetMetricData"]
    resources = ["*"]
  }
  statement {
    sid       = "NoPrivilegeEscape"
    effect    = "Deny"
    actions   = ["sts:AssumeRole", "iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:UpdateAssumeRolePolicy", "organizations:*", "ec2:CreateVpcPeeringConnection", "ec2:AcceptVpcPeeringConnection", "ec2:CreateTransitGateway*", "ram:*"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "boundary" {
  name   = "${local.prefix}-operator-boundary"
  policy = data.aws_iam_policy_document.boundary.json
  tags   = var.tags
}

resource "aws_iam_user" "operator" {
  name                 = "${local.prefix}-operator"
  permissions_boundary = aws_iam_policy.boundary.arn
  force_destroy        = true
  tags                 = var.tags
}

resource "aws_iam_user_policy" "operator" {
  name   = "${local.prefix}-restricted-operations"
  user   = aws_iam_user.operator.name
  policy = data.aws_iam_policy_document.boundary.json
}

output "vpc_id" { value = aws_vpc.lab.id }
output "subnet_id" { value = aws_subnet.lab.id }
output "trail_name" { value = aws_cloudtrail.lab.name }
output "trail_bucket_name" { value = aws_s3_bucket.trail.id }
output "guardduty_detector_id" { value = aws_guardduty_detector.lab.id }
output "operator_name" { value = aws_iam_user.operator.name }
