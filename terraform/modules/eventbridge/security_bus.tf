# CloudSec AI - EventBridge Security Bus (T02-03)
#
# A dedicated custom event bus for internal security events, isolated from
# the AWS default bus. All CloudSec AI internal events (FindingIngested,
# IncidentCreated, InvestigationStarted, ...) flow through this bus.
#
# Rules on this bus route to platform Lambdas, SNS topics, and DLQs (see
# terraform/modules/eventbridge/rules.tf for T02-08).
#
# Bus policy denies non-platform principals so an attacker cannot publish
# spoofed security events onto the bus.

resource "aws_cloudwatch_event_bus" "security_bus" {
  name = var.security_bus_name
  tags = merge(var.tags, {
    Name      = "cloudsec-${var.env_code}-security-bus"
    Component = "eventbridge"
  })
}

# Bus policy: restrict publishing to the platform's own account.
data "aws_iam_policy_document" "security_bus_policy" {
  statement {
    sid    = "AllowPlatformPublish"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.security_account_id}:root"]
    }

    actions   = ["events:PutEvents", "events:PutRule", "events:DeleteRule"]
    resources = [aws_cloudwatch_event_bus.security_bus.arn]
  }

  statement {
    sid    = "AllowEventBridgeServiceTargets"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    actions   = ["events:PutEvents", "events:PutRule"]
    resources = [aws_cloudwatch_event_bus.security_bus.arn]
  }

  statement {
    sid    = "DenyExternalPublishers"
    effect = "Deny"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions   = ["events:PutEvents", "events:PutRule"]
    resources = [aws_cloudwatch_event_bus.security_bus.arn]

    condition {
      test     = "StringNotEquals"
      variable = "aws:PrincipalAccount"
      values   = [var.security_account_id]
    }
  }
}

resource "aws_cloudwatch_event_bus_policy" "security_bus" {
  event_bus_name = aws_cloudwatch_event_bus.security_bus.name
  policy         = data.aws_iam_policy_document.security_bus_policy.json
}
