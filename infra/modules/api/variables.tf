variable "project_name" {
  description = "Project name prefix"
  type        = string
}

variable "stage_name" {
  description = "API Gateway deployment stage name"
  type        = string
  default     = "v1"
}

variable "post_scan_lambda_arn" {
  description = "ARN of the post-scan Lambda function"
  type        = string
}

variable "post_scan_function_name" {
  description = "Name of the post-scan Lambda function"
  type        = string
}

variable "get_scan_lambda_arn" {
  description = "ARN of the get-scan Lambda function"
  type        = string
}

variable "get_scan_function_name" {
  description = "Name of the get-scan Lambda function"
  type        = string
}

variable "get_history_lambda_arn" {
  description = "ARN of the get-history Lambda function"
  type        = string
}

variable "get_history_function_name" {
  description = "Name of the get-history Lambda function"
  type        = string
}

variable "rate_limit" {
  description = "Usage plan rate limit (requests per second)"
  type        = number
  default     = 50
}

variable "burst_limit" {
  description = "Usage plan burst limit"
  type        = number
  default     = 100
}

variable "quota_limit" {
  description = "Usage plan monthly request quota"
  type        = number
  default     = 100000
}

variable "tags" {
  description = "Resource tags"
  type        = map(string)
  default     = {}
}
