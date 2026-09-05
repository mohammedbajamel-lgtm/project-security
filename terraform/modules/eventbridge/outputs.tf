# Additional module-level outputs beyond those defined in security_bus.tf.
# Rule outputs are defined in rules.tf.

output "security_bus_name" {
  value       = aws_cloudwatch_event_bus.security_bus.name
  description = "Name of the CloudSec AI custom EventBridge bus"
}

output "security_bus_arn" {
  value       = aws_cloudwatch_event_bus.security_bus.arn
  description = "ARN of the CloudSec AI custom EventBridge bus"
}
