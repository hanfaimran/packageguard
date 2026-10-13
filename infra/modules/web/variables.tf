variable "project_name" {
  description = "Project name prefix"
  type        = string
}

variable "api_invoke_url" {
  description = "API Gateway invoke URL"
  type        = string
}

variable "api_key_value" {
  description = "API Gateway API Key value"
  type        = string
  sensitive   = true
}

variable "index_html_path" {
  description = "Local path to web/index.html"
  type        = string
}

variable "tags" {
  description = "Resource tags"
  type        = map(string)
  default     = {}
}
