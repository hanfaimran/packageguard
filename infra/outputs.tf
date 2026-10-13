output "api_invoke_url" {
  description = "Base invocation URL for the PackageGuard REST API"
  value       = module.api.invoke_url
}

output "api_key_id" {
  description = "ID of the API Gateway API Key"
  value       = module.api.api_key_id
}

output "api_key_value" {
  description = "Secret value of the API Gateway API Key"
  value       = module.api.api_key_value
  sensitive   = true
}

output "reports_bucket_name" {
  description = "Name of the KMS-encrypted S3 bucket storing reports"
  value       = module.storage.reports_bucket_name
}

output "scans_table_name" {
  description = "Name of the DynamoDB scans table"
  value       = module.storage.scans_table_name
}

output "watchlist_table_name" {
  description = "Name of the DynamoDB watchlist table"
  value       = module.storage.watchlist_table_name
}

output "kms_key_arn" {
  description = "ARN of the customer-managed KMS key"
  value       = module.kms.key_arn
}

output "alerts_topic_arn" {
  description = "ARN of the SNS alerts topic"
  value       = aws_sns_topic.alerts.arn
}

output "dashboard_url" {
  description = "HTTPS URL of the hosted web dashboard on CloudFront"
  value       = module.web.dashboard_url
}

