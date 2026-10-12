variable "project_name" {
  description = "Project name prefix"
  type        = string
}

variable "lambda_zip_dir" {
  description = "Directory containing the bundled zip files (default: infra/build)"
  type        = string
}

variable "scans_table_name" {
  description = "DynamoDB scans table name"
  type        = string
}

variable "scans_table_arn" {
  description = "DynamoDB scans table ARN"
  type        = string
}

variable "watchlist_table_name" {
  description = "DynamoDB watchlist table name"
  type        = string
}

variable "watchlist_table_arn" {
  description = "DynamoDB watchlist table ARN"
  type        = string
}

variable "reports_bucket_name" {
  description = "S3 reports bucket name"
  type        = string
}

variable "reports_bucket_arn" {
  description = "S3 reports bucket ARN"
  type        = string
}

variable "alerts_topic_arn" {
  description = "SNS alerts topic ARN"
  type        = string
}

variable "kms_key_arn" {
  description = "KMS key ARN"
  type        = string
}

variable "npm_registry_url" {
  description = "Default npm registry URL"
  type        = string
  default     = "https://registry.npmjs.org"
}

variable "tags" {
  description = "Resource tags"
  type        = map(string)
  default     = {}
}
