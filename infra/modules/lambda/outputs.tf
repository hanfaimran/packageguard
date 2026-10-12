output "post_scan_arn" {
  description = "ARN of the post-scan Lambda function"
  value       = aws_lambda_function.post_scan.arn
}

output "post_scan_function_name" {
  description = "Name of the post-scan Lambda function"
  value       = aws_lambda_function.post_scan.function_name
}

output "get_scan_arn" {
  description = "ARN of the get-scan Lambda function"
  value       = aws_lambda_function.get_scan.arn
}

output "get_scan_function_name" {
  description = "Name of the get-scan Lambda function"
  value       = aws_lambda_function.get_scan.function_name
}

output "get_history_arn" {
  description = "ARN of the get-history Lambda function"
  value       = aws_lambda_function.get_history.arn
}

output "get_history_function_name" {
  description = "Name of the get-history Lambda function"
  value       = aws_lambda_function.get_history.function_name
}

output "nightly_rescan_arn" {
  description = "ARN of the nightly-rescan Lambda function"
  value       = aws_lambda_function.nightly_rescan.arn
}

output "nightly_rescan_function_name" {
  description = "Name of the nightly-rescan Lambda function"
  value       = aws_lambda_function.nightly_rescan.function_name
}
