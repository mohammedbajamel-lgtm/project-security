# CloudSec AI - Dead Letter Queue (T02-04)
#
# Central DLQ for failed event processing. Failed deliveries from all
# platform EventBridge rules and processing SQS queues land here.
#
# Configuration
#   - 14-day message retention (long enough for forensic recovery).
#   - SSE-KMS with the finding key (T01-06).
#   - Queue policy restricts who can read from the DLQ.
#   - Dead-letter policy configured on processing queues (maxReceiveCount=3).
#
# The DLQ is deliberately kept separate from any processing queue because:
#   - DLQ failures must not cascade to the platform.
#   - Consumers of the DLQ must be explicit (recovery role).
#
# Access model
#   - CloudWatch can read DLQ attributes for metrics.
#   - Only the recovery role (T01-07) can consume messages from the DLQ.
#   - Only the EventBridge service and platform Lambdas can send to the DLQ.

resource "aws_sqs_queue" "dlq" {
  name                      = var.dlq_name
  message_retention_seconds = 1209600 # 14 days

  visibility_timeout_seconds = 120
  receive_wait_time_seconds  = 10
  max_message_size           = 262144

  kms_master_key_id = var.finding_key_arn

  tags = merge(var.tags, {
    Name            = "cloudsec-${var.env_code}-dlq"
    Component       = "sqs"
    DataSensitivity = "FINDINGS"
  })
}

# Redrive policy that will be attached to processing queues.
# This is a reusable policy string that consumers (EventBridge rules,
# processing queues) can reference. maxReceiveCount=3 means: after 3
# delivery attempts, redrive to the DLQ.
locals {
  redrive_policy_to_dlq = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dlq.arn
    maxReceiveCount     = 3
  })
}

# Queue policy: restrict who can read from the DLQ.
data "aws_iam_policy_document" "dlq_policy" {
  # Allow EventBridge to send failed events to the DLQ
  statement {
    effect = "Allow"
    sid    = "AllowEventBridgeToDLQ"

    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.dlq.arn]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }

  # Allow the correlation and investigation Lambdas to send errors to the DLQ.
  statement {
    effect = "Allow"
    sid    = "AllowPlatformLambdasToSend"

    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.dlq.arn]

    principals {
      type = "AWS"
      identifiers = [
        var.correlation_role_arn,
        var.investigation_role_arn,
        var.ingestion_role_arn,
      ]
    }
  }

  # Only the recovery role may read from the DLQ.
  statement {
    effect = "Allow"
    sid    = "AllowRecoveryRoleToConsume"

    actions = [
      "sqs:ReceiveMessage",
      "sqs:DeleteMessage",
      "sqs:GetQueueAttributes",
      "sqs:ChangeMessageVisibility",
    ]
    resources = [aws_sqs_queue.dlq.arn]

    principals {
      type        = "AWS"
      identifiers = [var.recovery_role_arn]
    }
  }

  # CloudWatch alarms can read DLQ attributes for metric collection.
  statement {
    effect = "Allow"
    sid    = "AllowCloudWatchMetrics"

    actions = [
      "sqs:GetQueueAttributes",
      "sqs:ListQueueTags",
    ]
    resources = [aws_sqs_queue.dlq.arn]

    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }
  }

  # Deny all other principals.
  statement {
    effect = "Deny"
    sid    = "DenyNonRecoveryReaders"

    actions = [
      "sqs:ReceiveMessage",
      "sqs:DeleteMessage",
    ]
    resources = [aws_sqs_queue.dlq.arn]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "aws:PrincipalArn"
      values   = [var.recovery_role_arn, var.terraform_deploy_role_arn]
    }
  }
}

resource "aws_sqs_queue_policy" "dlq" {
  queue_url = aws_sqs_queue.dlq.id
  policy    = data.aws_iam_policy_document.dlq_policy.json
}

# SQS publishes queue depth directly to AWS/SQS metrics, so a metric alarm is
# the correct primitive (CloudWatch log metric filters do not apply to SQS).
resource "aws_cloudwatch_metric_alarm" "dlq_depth" {
  alarm_name          = "cloudsec-${var.env_code}-dlq-depth"
  alarm_description   = "CloudSec DLQ contains ten or more failed events"
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = 10
  treat_missing_data  = "notBreaching"

  dimensions = {
    QueueName = aws_sqs_queue.dlq.name
  }

  alarm_actions = [var.alarm_topic_arn]

  tags = merge(var.tags, {
    Name      = "cloudsec-${var.env_code}-dlq-depth"
    Component = "cloudwatch"
  })
}

# KMS key policy grant: the DLQ can decrypt its own messages using
# the finding key. This is normally handled via the KMS key policy; the
# queue itself needs KMS:Decrypt on the master key's grant for
# aws_sqs_queue to encrypt messages on SendMessage. The finding key's
# policy already grants KMS usage to the ingestion/correlation/investigation
# roles which is where SendMessage is called.
# CloudWatch and events.amazonaws.com also need KMS:Decrypt for
# reading messages — handled by events.amazonaws.com's service policy.

output "dlq_arn" {
  value       = aws_sqs_queue.dlq.arn
  description = "ARN of the CloudSec AI DLQ"
}

output "dlq_url" {
  value       = aws_sqs_queue.dlq.id
  description = "URL of the CloudSec AI DLQ"
}

output "dlq_redrive_policy" {
  value       = local.redrive_policy_to_dlq
  description = "JSON redrive policy to attach to processing queues pointing at the DLQ"
}

output "dlq_depth_alarm_arn" {
  value       = aws_cloudwatch_metric_alarm.dlq_depth.arn
  description = "ARN of the DLQ depth CloudWatch alarm"
}
