variable "aws_region" {
  description = "AWS region for PackageGuard resources"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name identifier used for naming and tagging"
  type        = string
  default     = "packageguard"
}

variable "environment" {
  description = "Deployment environment (e.g., dev, staging, prod)"
  type        = string
  default     = "prod"
}

variable "alert_email" {
  description = "Email address for SNS security alerts subscription"
  type        = string
  default     = "security-alerts@example.com"
}

variable "npm_registry_url" {
  description = "Upstream npm registry URL"
  type        = string
  default     = "https://registry.npmjs.org"
}
