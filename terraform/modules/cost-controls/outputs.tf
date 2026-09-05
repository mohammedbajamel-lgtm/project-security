output "cost_alerts_topic_arn" {
  value = aws_sns_topic.cost_alerts.arn
}
output "monthly_budget_name" {
  value = var.monthly_budget_name
}
output "monthly_budget_limit" {
  value = var.monthly_budget_limit
}

output "cost_anomaly_monitor_arn" {
  value = aws_ce_anomaly_monitor.cloudsec.arn
}
