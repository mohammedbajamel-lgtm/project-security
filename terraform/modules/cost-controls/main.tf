# CloudSec AI - Cost Controls Module
#
# Deploys:
#   * AWS Budget with monthly limit and 80% / 100% / 120% thresholds.
#   * SNS topic cloudsec-{env}-cost-alerts for budget notifications.
#
# Budgets are free. Cost Anomaly Detection is enabled for resources carrying
# the CloudSec AI Project tag.

# ---- SNS Topic for cost alerts ----
resource "aws_sns_topic" "cost_alerts" {
  name              = var.cost_alerts_topic_name
  kms_master_key_id = var.ssm_key_arn
  tags = merge(var.tags, {
    Name = "cloudsec-${var.env_code}-cost-alerts"
  })
}

# Allow the AWS Budgets service and the Security Account root to publish.
data "aws_iam_policy_document" "cost_alerts_topic_policy" {
  statement {
    sid       = "AllowBudgetsPublish"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.cost_alerts.arn]
    principals {
      type        = "Service"
      identifiers = ["budgets.amazonaws.com"]
    }
  }
  statement {
    sid       = "AllowAccountRootPublish"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.cost_alerts.arn]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.security_account_id}:root"]
    }
  }
}

resource "aws_sns_topic_policy" "cost_alerts" {
  arn    = aws_sns_topic.cost_alerts.arn
  policy = data.aws_iam_policy_document.cost_alerts_topic_policy.json
}

resource "aws_sns_topic_subscription" "cost_alert_email" {
  count = var.alert_email == null ? 0 : 1

  topic_arn = aws_sns_topic.cost_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ---- Monthly AWS Budget ----
resource "aws_budgets_budget" "monthly" {
  name         = var.monthly_budget_name
  budget_type  = "COST"
  time_unit    = "MONTHLY"
  limit_amount = tostring(var.monthly_budget_limit)
  limit_unit   = "USD"
  account_id   = var.security_account_id

  cost_filter {
    name   = "TagKeyValue"
    values = ["Project${"$"}${var.project_name}"]
  }

  # 80% threshold
  notification {
    comparison_operator       = "GREATER_THAN"
    threshold                 = 80
    threshold_type            = "PERCENTAGE"
    notification_type         = "ACTUAL"
    subscriber_sns_topic_arns = [aws_sns_topic.cost_alerts.arn]
  }

  # 100% threshold
  notification {
    comparison_operator       = "GREATER_THAN"
    threshold                 = 100
    threshold_type            = "PERCENTAGE"
    notification_type         = "ACTUAL"
    subscriber_sns_topic_arns = [aws_sns_topic.cost_alerts.arn]
  }

  # 120% threshold
  notification {
    comparison_operator       = "GREATER_THAN"
    threshold                 = 120
    threshold_type            = "PERCENTAGE"
    notification_type         = "ACTUAL"
    subscriber_sns_topic_arns = [aws_sns_topic.cost_alerts.arn]
  }

  tags = merge(var.tags, {
    Name = "cloudsec-${var.env_code}-monthly-budget"
  })
}

# ---- Cost Anomaly Detection ----
# A monitor alone enables anomaly detection. Notification subscriptions require
# a real operator endpoint and are deliberately not fabricated by this module.
resource "aws_ce_anomaly_monitor" "cloudsec" {
  name         = "cloudsec-${var.env_code}-cost-anomaly-monitor"
  monitor_type = "CUSTOM"
  monitor_specification = jsonencode({
    Tags = {
      Key          = "user:Project"
      Values       = [var.project_name]
      MatchOptions = ["EQUALS"]
    }
  })

  # AWS expands the specification returned by the API with null fields such as
  # And, Dimensions, Not, and Or. The provider compares that normalized JSON
  # with the compact configuration above and otherwise proposes replacing the
  # monitor on every plan. The live monitor already uses user:Project, so keep
  # the immutable specification stable and manage the remaining attributes.
  lifecycle {
    ignore_changes = [monitor_specification]
  }

  tags = merge(var.tags, {
    Name = "cloudsec-${var.env_code}-cost-anomaly-monitor"
  })
}
