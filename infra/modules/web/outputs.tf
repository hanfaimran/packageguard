output "bucket_name" {
  description = "Name of the web dashboard S3 bucket"
  value       = aws_s3_bucket.web.id
}

output "cloudfront_distribution_id" {
  description = "ID of the CloudFront distribution"
  value       = aws_cloudfront_distribution.web.id
}

output "cloudfront_domain_name" {
  description = "Domain name of the CloudFront distribution"
  value       = aws_cloudfront_distribution.web.domain_name
}

output "dashboard_url" {
  description = "HTTPS URL of the hosted web dashboard"
  value       = "https://${aws_cloudfront_distribution.web.domain_name}"
}
