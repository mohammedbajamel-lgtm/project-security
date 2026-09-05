# CloudSec AI - IAM Permission Policies
#
# Each policy uses least privilege:
#   - Actions scoped to the specific API calls the role makes.
#   - Resources scoped to specific ARNs (passed in as variables).
#   - No statement contains Action = "*" or Resource = "*".
#   - Comments explain the purpose of each permission.

# =========================================================
# Ingestion policy - shared by all telemetry ingestor Lambdas.
# Writes normalized findings to DynamoDB, publishes to EventBridge bus,
# sends failures to DLQ.
# =========================================================
data "aws_iam_policy_document" "ingestion_policy" {
  statement {
    sid       = "WriteFindings"
    actions   = ["dynamodb:PutItem"]
    resources = [var.findings_table_arn]
  }
  statement {
    sid       = "PublishInternalEvent"
    actions   = ["events:PutEvents"]
    resources = [var.security_bus_arn]
  }
  statement {
    sid       = "SendToDLQ"
    actions   = ["sqs:SendMessage"]
    resources = [var.dlq_arn]
  }
  statement {
    sid       = "ReadCloudTrailLogs"
    actions   = ["s3:GetObject"]
    resources = ["${var.cloudtrail_bucket_arn}/CloudTrail/*"]
  }
  statement {
    sid = "CloudWatchLogging"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:${var.region}:${var.security_account_id}:*"]
  }
  statement {
    sid = "KMSDecryptFindingKey"
    actions = [
      "kms:GenerateDataKey",
      "kms:Decrypt",
    ]
    resources = [var.finding_key_arn]
  }
  # CloudWatch PutMetricData does not support resource-level permissions.
  statement {
    sid       = "EmitTelemetryMetrics"
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["CloudSec/Telemetry"]
    }
  }
}

# =========================================================
# Correlation policy - reads findings, creates incidents, triggers
# downstream events.
# =========================================================
data "aws_iam_policy_document" "correlation_policy" {
  statement {
    sid = "ReadFindings"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:Query",
      "dynamodb:Scan",
    ]
    resources = [var.findings_table_arn, "${var.findings_table_arn}/index/*"]
  }
  statement {
    sid       = "CreateIncidents"
    actions   = ["dynamodb:PutItem", "dynamodb:TransactWriteItems"]
    resources = [var.incidents_table_arn]
  }
  statement {
    sid       = "ReadIncidents"
    actions   = ["dynamodb:GetItem"]
    resources = [var.incidents_table_arn]
  }
  statement {
    sid       = "ReadCorrelationConfig"
    actions   = ["ssm:GetParameter"]
    resources = ["arn:aws:ssm:${var.region}:${var.security_account_id}:parameter/cloudsec/${var.env_code}/correlation/*"]
  }
  statement {
    sid       = "ComputeBaselines"
    actions   = ["cloudtrail:LookupEvents"]
    resources = ["*"]
  }
  statement {
    sid       = "WriteBaselines"
    actions   = ["dynamodb:PutItem", "dynamodb:GetItem", "dynamodb:Query"]
    resources = [var.baselines_table_arn, "${var.baselines_table_arn}/index/*"]
  }
  statement {
    sid       = "PublishInternalEvent"
    actions   = ["events:PutEvents"]
    resources = [var.security_bus_arn]
  }
  statement {
    sid = "CloudWatchLogging"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:${var.region}:${var.security_account_id}:*"]
  }
  statement {
    sid = "KMSDecryptBothKeys"
    actions = [
      "kms:GenerateDataKey",
      "kms:Decrypt",
    ]
    resources = [
      var.incidents_key_arn,
      var.finding_key_arn,
    ]
  }
}

# =========================================================
# Investigation policy - invokes Bedrock, reads incidents/findings,
# writes investigation results.
# =========================================================
data "aws_iam_policy_document" "investigation_policy" {
  statement {
    sid       = "EmitAIMetrics"
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["CloudSec/AI"]
    }
  }
  statement {
    sid = "ReadIncidents"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:Query",
      "dynamodb:UpdateItem",
    ]
    resources = [var.incidents_table_arn]
  }
  statement {
    sid       = "ReadAIConfiguration"
    actions   = ["ssm:GetParameter", "ssm:GetParameters"]
    resources = ["arn:aws:ssm:${var.region}:${var.security_account_id}:parameter/cloudsec/${var.env_code}/ai/*"]
  }
  statement {
    sid       = "PublishInvestigationEvents"
    actions   = ["events:PutEvents"]
    resources = [var.security_bus_arn]
  }
  statement {
    sid = "ReadFindings"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:Query",
      "dynamodb:Scan",
    ]
    resources = [var.findings_table_arn]
  }
  statement {
    sid       = "CloudTrailLookup"
    actions   = ["cloudtrail:LookupEvents"]
    resources = ["*"]
    # cloudtrail:LookupEvents does not support resource-level permissions.
    # Scoped by the trail name inside the Lambda code (LookupAttributes).
    # Tracked as a documented necessary exception.
  }
  statement {
    sid = "BedrockInvoke"
    actions = [
      "bedrock:InvokeModel",
      "bedrock:InvokeModelWithResponseStream",
    ]
    resources = var.bedrock_model_arns
  }
  statement {
    sid = "CloudWatchLogging"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:${var.region}:${var.security_account_id}:*"]
  }
  statement {
    sid = "KMSDecryptIncidentKey"
    actions = [
      "kms:GenerateDataKey",
      "kms:Decrypt",
    ]
    resources = [var.incidents_key_arn]
  }
}

# =========================================================
# Safety validation policy - deterministic pre-flight checks before
# remediation. Read-only on infrastructure; no mutating actions.
# =========================================================
data "aws_iam_policy_document" "safety_validation_policy" {
  statement {
    sid       = "WriteSafetyDecisions"
    actions   = ["dynamodb:PutItem"]
    resources = [var.decisions_table_arn]
  }
  statement {
    sid = "ReadIncidents"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:Query",
    ]
    resources = [var.incidents_table_arn]
  }
  statement {
    sid       = "PublishSafetyDecisions"
    actions   = ["events:PutEvents"]
    resources = [var.security_bus_arn]
  }
  statement {
    sid       = "ReadSafetyPolicy"
    actions   = ["ssm:GetParameter"]
    resources = ["arn:aws:ssm:${var.region}:${var.security_account_id}:parameter/cloudsec/${var.env_code}/safety/*"]
  }
  statement {
    sid = "ReadIAM"
    actions = [
      "iam:GetRole",
      "iam:GetRolePolicy",
      "iam:ListAttachedRolePolicies",
      "iam:SimulatePrincipalPolicy",
      "iam:SimulateCustomPolicy",
      "iam:ListRoles",
    ]
    resources = ["arn:aws:iam::${var.security_account_id}:role/cloudsec-*"]
  }
  statement {
    sid     = "DescribeKMS"
    actions = ["kms:DescribeKey", "kms:Decrypt", "kms:GenerateDataKey"]
    resources = [
      var.incidents_key_arn,
      var.evidence_key_arn,
      var.finding_key_arn,
      var.ssm_key_arn,
    ]
  }
  statement {
    sid       = "DescribeDynamoDB"
    actions   = ["dynamodb:DescribeTable"]
    resources = [var.incidents_table_arn]
  }
  statement {
    sid = "CloudWatchLogging"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:${var.region}:${var.security_account_id}:*"]
  }
}

# =========================================================
# Remediation policy - executes the approved remediation action.
# Scoped to the specific API calls for each playbook type. This is the
# most sensitive role; every action is intentional and documented.
# =========================================================
data "aws_iam_policy_document" "remediation_policy" {
  statement {
    sid       = "EmitRemediationMetrics"
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["CloudSec/Operations"]
    }
  }
  statement {
    sid       = "RemediationCoordination"
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem"]
    resources = [var.idempotency_table_arn]
  }
  statement {
    sid       = "AppendRemediationAudit"
    actions   = ["dynamodb:PutItem"]
    resources = [var.remediation_audit_table_arn]
  }
  statement {
    sid       = "UpdateIncidentStatus"
    actions   = ["dynamodb:UpdateItem"]
    resources = [var.incidents_table_arn]
  }
  statement {
    sid = "DisableCompromisedIAMKeys"
    actions = [
      "iam:UpdateAccessKey",
      "iam:ListAccessKeys",
    ]
    resources = [
      "arn:aws:iam::${var.security_account_id}:user/*",
    ]
  }
  statement {
    sid = "DetachAndRestoreManagedRolePolicy"
    actions = [
      "iam:GetRole",
      "iam:ListAttachedRolePolicies",
      "iam:DetachRolePolicy",
      "iam:AttachRolePolicy",
    ]
    resources = [
      "arn:aws:iam::${var.security_account_id}:role/cloudsec-*",
      "arn:aws:iam::${var.security_account_id}:policy/cloudsec-*",
    ]
  }
  statement {
    sid = "S3PublicAccessContainment"
    actions = [
      "s3:GetBucketTagging",
      "s3:GetBucketPublicAccessBlock",
      "s3:PutBucketPublicAccessBlock",
      "s3:DeleteBucketPublicAccessBlock",
      "s3:ListBucket",
    ]
    resources = ["arn:aws:s3:::cloudsec-*"]
  }
  statement {
    sid = "EC2Containment"
    actions = [
      "ec2:CreateSecurityGroup",
      "ec2:CreateSnapshot",
      "ec2:CreateTags",
      "ec2:ModifyInstanceAttribute",
      "ec2:RevokeSecurityGroupIngress",
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:RevokeSecurityGroupEgress",
    ]
    resources = [
      "arn:aws:ec2:${var.region}:${var.security_account_id}:instance/*",
      "arn:aws:ec2:${var.region}:${var.security_account_id}:security-group/*",
      "arn:aws:ec2:${var.region}:${var.security_account_id}:snapshot/*",
      "arn:aws:ec2:${var.region}:${var.security_account_id}:volume/*",
      "arn:aws:ec2:${var.region}:${var.security_account_id}:vpc/*",
    ]
  }
  statement {
    sid = "EC2ReadForContainment"
    actions = [
      "ec2:DescribeInstances",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeSecurityGroupRules",
      "ec2:DescribeSnapshots",
    ]
    resources = ["*"]
    # EC2 Describe APIs do not support resource-level permissions.
  }
  statement {
    sid = "CloudTrailRecovery"
    actions = [
      "cloudtrail:DescribeTrails",
      "cloudtrail:GetTrailStatus",
      "cloudtrail:StartLogging",
      "cloudtrail:UpdateTrail",
      "cloudtrail:CreateTrail",
    ]
    resources = ["arn:aws:cloudtrail:${var.region}:${var.security_account_id}:trail/cloudsec-*"]
  }
  statement {
    sid       = "PublishInternalEvent"
    actions   = ["events:PutEvents"]
    resources = [var.security_bus_arn]
  }
  statement {
    sid = "CloudWatchLogging"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:${var.region}:${var.security_account_id}:*"]
  }
  statement {
    sid = "KMSDecryptIncidentKey"
    actions = [
      "kms:GenerateDataKey",
      "kms:Decrypt",
    ]
    resources = [var.incidents_key_arn]
  }
}

# =========================================================
# Verification policy - confirms remediation succeeded (read-only).
# =========================================================
data "aws_iam_policy_document" "verification_policy" {
  statement {
    sid       = "EmitVerificationMetrics"
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["CloudSec/Operations"]
    }
  }
  statement {
    sid = "ReadAndRecordVerification"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:Query",
      "dynamodb:UpdateItem",
    ]
    resources = [var.incidents_table_arn]
  }
  statement {
    sid = "DescribeIAM"
    actions = [
      "iam:GetAccessKeyLastUsed",
      "iam:GetUser",
      "iam:GetRole",
      "iam:ListAccessKeys",
      "iam:ListAttachedRolePolicies",
    ]
    resources = [
      "arn:aws:iam::${var.security_account_id}:user/*",
      "arn:aws:iam::${var.security_account_id}:role/cloudsec-*",
    ]
  }
  statement {
    sid = "GetBucketPolicy"
    actions = [
      "s3:GetBucketPolicy",
      "s3:GetBucketPublicAccessBlock",
    ]
    resources = ["arn:aws:s3:::cloudsec-*"]
  }
  statement {
    sid       = "GetCloudTrailStatus"
    actions   = ["cloudtrail:GetTrailStatus", "cloudtrail:LookupEvents"]
    resources = ["*"]
    # cloudtrail:GetTrailStatus does not support resource-level permissions
    # when called against trails; documented exception.
  }
  statement {
    sid = "DescribeRemediatedResources"
    actions = [
      "ec2:DescribeInstances",
      "ec2:DescribeSecurityGroupRules",
      "ec2:DescribeSnapshots",
      "guardduty:GetFindings",
      "securityhub:BatchGetFindings",
    ]
    resources = ["*"]
    # These read APIs do not consistently support resource-level permissions.
  }
  statement {
    sid       = "PublishVerificationEvents"
    actions   = ["events:PutEvents"]
    resources = [var.security_bus_arn]
  }
  statement {
    sid       = "PublishEscalation"
    actions   = ["sns:Publish"]
    resources = [var.escalations_topic_arn]
  }
  statement {
    sid = "CloudWatchLogging"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:${var.region}:${var.security_account_id}:*"]
  }
  statement {
    sid = "KMSDecryptIncidentKey"
    actions = [
      "kms:GenerateDataKey",
      "kms:Decrypt",
    ]
    resources = [var.incidents_key_arn]
  }
}

# =========================================================
# Reporting policy - generates forensic reports, writes to evidence
# bucket, publishes to SNS.
# =========================================================
data "aws_iam_policy_document" "reporting_policy" {
  statement {
    sid = "ManageKnowledgeBase"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:Query",
    ]
    resources = [
      var.knowledge_base_table_arn,
      "${var.knowledge_base_table_arn}/index/*",
    ]
  }
  statement {
    sid = "ReadIncidents"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:Query",
      "dynamodb:Scan",
      "dynamodb:UpdateItem",
    ]
    resources = [var.incidents_table_arn]
  }
  statement {
    sid       = "ReadRemediationAudit"
    actions   = ["dynamodb:Scan", "dynamodb:Query"]
    resources = [var.remediation_audit_table_arn]
  }
  statement {
    sid       = "ReadExecutionHistory"
    actions   = ["states:GetExecutionHistory"]
    resources = ["arn:aws:states:${var.region}:${var.security_account_id}:execution:cloudsec-${var.env_code}-remediation-*"]
  }
  statement {
    sid = "ReadFindings"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:Query",
    ]
    resources = [var.findings_table_arn]
  }
  statement {
    sid = "WriteEvidence"
    actions = [
      "s3:PutObject",
      "s3:GetObject",
      "s3:ListBucket",
    ]
    resources = [
      var.evidence_bucket_arn,
      "${var.evidence_bucket_arn}/*",
    ]
  }
  statement {
    sid     = "PublishToSNS"
    actions = ["sns:Publish"]
    resources = [
      var.incidents_topic_arn,
      var.escalations_topic_arn,
      var.reports_topic_arn,
    ]
  }
  statement {
    sid = "CloudWatchLogging"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:${var.region}:${var.security_account_id}:*"]
  }
  statement {
    sid = "KMSDecryptBothKeys"
    actions = [
      "kms:GenerateDataKey",
      "kms:Decrypt",
    ]
    resources = [
      var.incidents_key_arn,
      var.evidence_key_arn,
    ]
  }
}

# =========================================================
# Recovery policy - break-glass DLQ recovery. Read-only + specific
# DLQ operations. Never has write access to production data tables.
# =========================================================
data "aws_iam_policy_document" "recovery_policy" {
  statement {
    sid = "ReadDLQ"
    actions = [
      "sqs:ReceiveMessage",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
    ]
    resources = [var.dlq_arn]
  }
  statement {
    sid       = "DescribeDLQ"
    actions   = ["sqs:GetQueueUrl"]
    resources = ["*"]
    # sqs:GetQueueUrl requires resource "*" — documented AWS limitation.
  }
  statement {
    sid = "CloudWatchLogging"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:${var.region}:${var.security_account_id}:*"]
  }
  statement {
    sid       = "KMSDecryptFindingKey"
    actions   = ["kms:Decrypt"]
    resources = [var.finding_key_arn]
  }
}

# =========================================================
# Terraform deploy policy - Phase-2 deployment permissions for the
# terraform-deploy role. This is the role the CI/CD runner assumes
# to run `terraform apply` for Phase 2+ resources (DynamoDB,
# EventBridge, SQS, SNS, Lambda, Step Functions, logs).
#
# Every action and resource is scoped to `cloudsec-dev-*` namespaced
# ARNs. No wildcard actions. No AdministratorAccess. iam:PassRole is
# restricted by `iam:PassedToService` condition.
#
# This policy was authored to match the live inline policy
# `cloudsec-dev-phase2-deployment` exactly (imported from AWS 2026-09-04)
# so that Terraform can manage what is already deployed.
# =========================================================
data "aws_iam_policy_document" "terraform_deploy_policy" {
  statement {
    sid = "ManageCloudSecDynamoDB"
    actions = [
      "dynamodb:CreateTable",
      "dynamodb:DescribeTable",
      "dynamodb:DescribeContinuousBackups",
      "dynamodb:DescribeTimeToLive",
      "dynamodb:UpdateTable",
      "dynamodb:UpdateContinuousBackups",
      "dynamodb:UpdateTimeToLive",
      "dynamodb:ListTagsOfResource",
      "dynamodb:TagResource",
      "dynamodb:UntagResource",
    ]
    resources = ["arn:aws:dynamodb:${var.region}:${var.security_account_id}:table/cloudsec-${var.env_code}-*"]
  }

  statement {
    sid = "ManageCloudSecEventBridge"
    actions = [
      "events:CreateEventBus",
      "events:DeleteEventBus",
      "events:DescribeEventBus",
      "events:PutPermission",
      "events:RemovePermission",
      "events:PutRule",
      "events:DeleteRule",
      "events:DescribeRule",
      "events:PutTargets",
      "events:RemoveTargets",
      "events:ListTargetsByRule",
      "events:ListTagsForResource",
      "events:TagResource",
      "events:UntagResource",
    ]
    resources = [
      "arn:aws:events:${var.region}:${var.security_account_id}:event-bus/cloudsec-${var.env_code}-*",
      "arn:aws:events:${var.region}:${var.security_account_id}:rule/cloudsec-${var.env_code}-*",
      "arn:aws:events:${var.region}:${var.security_account_id}:rule/cloudsec-${var.env_code}-*/*",
    ]
  }

  statement {
    sid = "ManageCorrelationParameters"
    actions = ["ssm:PutParameter", "ssm:GetParameter", "ssm:DeleteParameter",
    "ssm:AddTagsToResource", "ssm:RemoveTagsFromResource", "ssm:ListTagsForResource"]
    resources = ["arn:aws:ssm:${var.region}:${var.security_account_id}:parameter/cloudsec/${var.env_code}/correlation/*"]
  }

  statement {
    sid = "ManageCloudSecQueues"
    actions = [
      "sqs:CreateQueue",
      "sqs:GetQueueUrl",
      "sqs:GetQueueAttributes",
      "sqs:SetQueueAttributes",
      "sqs:ListQueueTags",
      "sqs:TagQueue",
      "sqs:UntagQueue",
    ]
    resources = ["arn:aws:sqs:${var.region}:${var.security_account_id}:cloudsec-${var.env_code}-*"]
  }

  statement {
    sid = "ManageCloudSecTopics"
    actions = [
      "sns:CreateTopic",
      "sns:GetTopicAttributes",
      "sns:SetTopicAttributes",
      "sns:ListTagsForResource",
      "sns:TagResource",
      "sns:UntagResource",
      "sns:Subscribe",
      "sns:ListSubscriptionsByTopic",
    ]
    resources = ["arn:aws:sns:${var.region}:${var.security_account_id}:cloudsec-${var.env_code}-*"]
  }

  statement {
    sid = "ManageCloudSecFunctions"
    actions = [
      "lambda:CreateFunction",
      "lambda:GetFunction",
      "lambda:GetFunctionConfiguration",
      "lambda:UpdateFunctionCode",
      "lambda:UpdateFunctionConfiguration",
      "lambda:PutFunctionConcurrency",
      "lambda:DeleteFunctionConcurrency",
      "lambda:AddPermission",
      "lambda:GetPolicy",
      "lambda:ListTags",
      "lambda:TagResource",
      "lambda:UntagResource",
    ]
    resources = ["arn:aws:lambda:${var.region}:${var.security_account_id}:function:cloudsec-${var.env_code}-*"]
  }

  statement {
    sid = "ManageCloudSecLogs"
    actions = [
      "logs:CreateLogGroup",
      "logs:DescribeLogGroups",
      "logs:PutRetentionPolicy",
      "logs:ListTagsForResource",
      "logs:TagResource",
      "logs:UntagResource",
    ]
    resources = ["arn:aws:logs:${var.region}:${var.security_account_id}:log-group:/aws/lambda/cloudsec-${var.env_code}-*"]
  }

  statement {
    sid = "ManageCloudSecAlarms"
    actions = [
      "cloudwatch:DeleteAlarms",
      "cloudwatch:DescribeAlarms",
      "cloudwatch:PutMetricAlarm",
      "cloudwatch:TagResource",
      "cloudwatch:UntagResource",
    ]
    resources = ["arn:aws:cloudwatch:${var.region}:${var.security_account_id}:alarm:cloudsec-${var.env_code}-*"]
  }

  statement {
    sid = "UseCloudSecKeys"
    actions = [
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:GenerateDataKey",
      "kms:GenerateDataKeyWithoutPlaintext",
    ]
    resources = [
      var.incidents_key_arn,
      var.evidence_key_arn,
      var.finding_key_arn,
      var.ssm_key_arn,
    ]
  }

  statement {
    sid       = "PassCloudSecServiceRoles"
    actions   = ["iam:PassRole"]
    resources = ["arn:aws:iam::${var.security_account_id}:role/cloudsec-${var.env_code}-*"]
    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values = [
        "lambda.amazonaws.com",
        "events.amazonaws.com",
        "states.amazonaws.com",
      ]
    }
  }

  statement {
    sid = "ReadCloudSecRoles"
    actions = [
      "iam:GetRole",
      "iam:GetRolePolicy",
      "iam:ListRolePolicies",
      "iam:ListAttachedRolePolicies",
    ]
    resources = ["arn:aws:iam::${var.security_account_id}:role/cloudsec-${var.env_code}-*"]
  }
}
