output "rest_api_id" {
  description = "ID of the REST API"
  value       = aws_api_gateway_rest_api.main.id
}

output "invoke_url" {
  description = "Invocation URL of the deployed API stage"
  value       = aws_api_gateway_stage.v1.invoke_url
}

output "api_key_value" {
  description = "Value of the generated API key (sensitive)"
  value       = aws_api_gateway_api_key.main.value
  sensitive   = true
}

output "api_key_id" {
  description = "ID of the generated API key"
  value       = aws_api_gateway_api_key.main.id
}
