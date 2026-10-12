variable "project_name" {
  description = "Project name prefix"
  type        = string
}

variable "alerts_topic_arn" {
  description = "ARN of the SNS alerts topic"
  type        = string
}

variable "nightly_rescan_lambda_arn" {
  description = "ARN of the nightly-rescan Lambda function"
  type        = string
}

variable "nightly_rescan_function_name" {
  description = "Function name of the nightly-rescan Lambda function"
  type        = string
}

variable "lambda_function_names" {
  description = "List of all Lambda function names to monitor with error alarms"
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Resource tags"
  type        = map(string)
  default     = {}
}
