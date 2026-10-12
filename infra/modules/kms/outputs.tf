output "key_arn" {
  description = "The ARN of the KMS key"
  value       = aws_kms_key.main.arn
}

output "key_id" {
  description = "The globally unique identifier for the KMS key"
  value       = aws_kms_key.main.key_id
}

output "key_alias" {
  description = "The alias of the KMS key"
  value       = aws_kms_alias.main.name
}
