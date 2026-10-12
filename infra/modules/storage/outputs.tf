output "reports_bucket_name" {
  description = "Name of the S3 bucket storing full JSON reports"
  value       = aws_s3_bucket.reports.id
}

output "reports_bucket_arn" {
  description = "ARN of the S3 reports bucket"
  value       = aws_s3_bucket.reports.arn
}

output "scans_table_name" {
  description = "Name of the DynamoDB scans table"
  value       = aws_dynamodb_table.scans.name
}

output "scans_table_arn" {
  description = "ARN of the DynamoDB scans table"
  value       = aws_dynamodb_table.scans.arn
}

output "watchlist_table_name" {
  description = "Name of the DynamoDB watchlist table"
  value       = aws_dynamodb_table.watchlist.name
}

output "watchlist_table_arn" {
  description = "ARN of the DynamoDB watchlist table"
  value       = aws_dynamodb_table.watchlist.arn
}
