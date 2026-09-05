# CloudSec AI - SNS Notification Topics (T02-07)
#
# Three topics used by the platform:
#   * incidents  - incident lifecycle notifications (created, resolved, escalated)
#   * escalations - escalation and verification-failure alerts (requires human review)
#   * errors     - system-level error notifications (unhandled Lambda errors, etc.)
#
# All topics are KMS-encrypted with the incident key (T01-06).
#
# Subscription policy restricts who can subscribe. Automated topics
# (escalations, errors) intentionally have NO email subscribers by default.

resource "aws_sns_topic" "incidents" {
  name              = var.incidents_topic_name
  kms_master_key_id = var.incident_key_arn

  tags = merge(var.tags, {
    Name      = "cloudsec-${var.env_code}-incidents"
    Component = "sns"
    TopicType = "incident-lifecycle"
  })
}

resource "aws_sns_topic" "escalations" {
  name              = var.escalations_topic_name
  kms_master_key_id = var.incident_key_arn

  tags = merge(var.tags, {
    Name      = "cloudsec-${var.env_code}-escalations"
    Component = "sns"
    TopicType = "human-escalation"
  })
}

resource "aws_sns_topic" "errors" {
  name              = var.errors_topic_name
  kms_master_key_id = var.incident_key_arn

  tags = merge(var.tags, {
    Name      = "cloudsec-${var.env_code}-errors"
    Component = "sns"
    TopicType = "system-error"
  })
}

resource "aws_sns_topic" "reports" {
  name              = var.reports_topic_name
  kms_master_key_id = var.incident_key_arn

  tags = merge(var.tags, {
    Name      = "cloudsec-${var.env_code}-reports"
    Component = "sns"
    TopicType = "incident-report"
  })
}

# Topic policy: restrict subscriptions to known CloudSec AI principals.
data "aws_iam_policy_document" "incidents_topic_policy" {
  # Allow the platform to publish to the topic.
  statement {
    effect = "Allow"
    sid    = "AllowPlatformPublish"

    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.incidents.arn]

    principals {
      type = "AWS"
      identifiers = [
        var.correlation_role_arn,
        var.investigation_role_arn,
        var.safety_validation_role_arn,
        var.verification_role_arn,
        var.reporting_role_arn,
      ]
    }
  }

  # Allow EventBridge to publish from rules to the topic.
  statement {
    effect = "Allow"
    sid    = "AllowEventBridgePublish"

    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.incidents.arn]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }

  # Only the terraform deploy role may subscribe.
  statement {
    effect = "Allow"
    sid    = "AllowTerraformSubscribe"

    actions   = ["sns:Subscribe"]
    resources = [aws_sns_topic.incidents.arn]

    principals {
      type        = "AWS"
      identifiers = [var.terraform_deploy_role_arn]
    }
  }
}

resource "aws_sns_topic_policy" "incidents" {
  arn    = aws_sns_topic.incidents.arn
  policy = data.aws_iam_policy_document.incidents_topic_policy.json
}

# The escalations and errors topics use the same policy shape; inlined as
# copies because Terraform SNS topic policy is per-topic.

data "aws_iam_policy_document" "escalations_topic_policy" {
  statement {
    effect = "Allow"
    sid    = "AllowPlatformPublish"

    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.escalations.arn]

    principals {
      type = "AWS"
      identifiers = [
        var.correlation_role_arn,
        var.investigation_role_arn,
        var.safety_validation_role_arn,
        var.verification_role_arn,
        var.reporting_role_arn,
      ]
    }
  }

  statement {
    effect = "Allow"
    sid    = "AllowEventBridgePublish"

    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.escalations.arn]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }

  statement {
    effect = "Allow"
    sid    = "AllowTerraformSubscribe"

    actions   = ["sns:Subscribe"]
    resources = [aws_sns_topic.escalations.arn]

    principals {
      type        = "AWS"
      identifiers = [var.terraform_deploy_role_arn]
    }
  }
}

resource "aws_sns_topic_policy" "escalations" {
  arn    = aws_sns_topic.escalations.arn
  policy = data.aws_iam_policy_document.escalations_topic_policy.json
}

data "aws_iam_policy_document" "errors_topic_policy" {
  statement {
    effect = "Allow"
    sid    = "AllowPlatformPublish"

    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.errors.arn]

    principals {
      type = "AWS"
      identifiers = [
        var.correlation_role_arn,
        var.investigation_role_arn,
        var.safety_validation_role_arn,
        var.verification_role_arn,
        var.reporting_role_arn,
        var.ingestion_role_arn,
      ]
    }
  }

  statement {
    effect = "Allow"
    sid    = "AllowEventBridgePublish"

    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.errors.arn]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }

  statement {
    effect = "Allow"
    sid    = "AllowTerraformSubscribe"

    actions   = ["sns:Subscribe"]
    resources = [aws_sns_topic.errors.arn]

    principals {
      type        = "AWS"
      identifiers = [var.terraform_deploy_role_arn]
    }
  }
}

resource "aws_sns_topic_policy" "errors" {
  arn    = aws_sns_topic.errors.arn
  policy = data.aws_iam_policy_document.errors_topic_policy.json
}

data "aws_iam_policy_document" "reports_topic_policy" {
  statement {
    sid       = "AllowReportingPublish"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.reports.arn]
    principals {
      type        = "AWS"
      identifiers = [var.reporting_role_arn]
    }
  }
  statement {
    sid       = "AllowTerraformSubscribe"
    effect    = "Allow"
    actions   = ["sns:Subscribe"]
    resources = [aws_sns_topic.reports.arn]
    principals {
      type        = "AWS"
      identifiers = [var.terraform_deploy_role_arn]
    }
  }
}

resource "aws_sns_topic_policy" "reports" {
  arn    = aws_sns_topic.reports.arn
  policy = data.aws_iam_policy_document.reports_topic_policy.json
}

output "incidents_topic_arn" {
  value       = aws_sns_topic.incidents.arn
  description = "ARN of the incident lifecycle notifications topic"
}

output "escalations_topic_arn" {
  value       = aws_sns_topic.escalations.arn
  description = "ARN of the escalation alerts topic"
}

output "errors_topic_arn" {
  value       = aws_sns_topic.errors.arn
  description = "ARN of the system error notifications topic"
}

output "reports_topic_arn" {
  value       = aws_sns_topic.reports.arn
  description = "ARN of the stakeholder incident reports topic"
}
