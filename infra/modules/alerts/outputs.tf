output "nightly_rule_arn" {
  description = "ARN of the EventBridge nightly rescan rule"
  value       = aws_cloudwatch_event_rule.nightly.arn
}
