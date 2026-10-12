variable "project_name" {
  description = "Project name prefix"
  type        = string
}

variable "kms_key_arn" {
  description = "KMS Key ARN for server-side encryption"
  type        = string
}

variable "tags" {
  description = "Resource tags"
  type        = map(string)
  default     = {}
}
