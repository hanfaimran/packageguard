# ---------------------------------------------------------------------------
# API Gateway REST API
# ---------------------------------------------------------------------------
resource "aws_api_gateway_rest_api" "main" {
  name        = "${var.project_name}-api"
  description = "PackageGuard Trust Verification REST API"

  endpoint_configuration {
    types = ["REGIONAL"]
  }

  tags = var.tags
}

# ---------------------------------------------------------------------------
# API Resources
# /scan
# /scan/{id}
# /history
# ---------------------------------------------------------------------------
resource "aws_api_gateway_resource" "scan" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  parent_id   = aws_api_gateway_rest_api.main.root_resource_id
  path_part   = "scan"
}

resource "aws_api_gateway_resource" "scan_id" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  parent_id   = aws_api_gateway_resource.scan.id
  path_part   = "{id}"
}

resource "aws_api_gateway_resource" "history" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  parent_id   = aws_api_gateway_rest_api.main.root_resource_id
  path_part   = "history"
}

# ---------------------------------------------------------------------------
# Method 1: POST /scan (Requires API Key)
# ---------------------------------------------------------------------------
resource "aws_api_gateway_method" "post_scan" {
  rest_api_id      = aws_api_gateway_rest_api.main.id
  resource_id      = aws_api_gateway_resource.scan.id
  http_method      = "POST"
  authorization    = "NONE"
  api_key_required = true
}

resource "aws_api_gateway_integration" "post_scan" {
  rest_api_id             = aws_api_gateway_rest_api.main.id
  resource_id             = aws_api_gateway_resource.scan.id
  http_method             = aws_api_gateway_method.post_scan.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = "arn:aws:apigateway:${data.aws_region.current.name}:lambda:path/2015-03-31/functions/${var.post_scan_lambda_arn}/invocations"
}

# ---------------------------------------------------------------------------
# Method 2: GET /scan/{id} (Requires API Key)
# ---------------------------------------------------------------------------
resource "aws_api_gateway_method" "get_scan" {
  rest_api_id      = aws_api_gateway_rest_api.main.id
  resource_id      = aws_api_gateway_resource.scan_id.id
  http_method      = "GET"
  authorization    = "NONE"
  api_key_required = true
}

resource "aws_api_gateway_integration" "get_scan" {
  rest_api_id             = aws_api_gateway_rest_api.main.id
  resource_id             = aws_api_gateway_resource.scan_id.id
  http_method             = aws_api_gateway_method.get_scan.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = "arn:aws:apigateway:${data.aws_region.current.name}:lambda:path/2015-03-31/functions/${var.get_scan_lambda_arn}/invocations"
}

# ---------------------------------------------------------------------------
# Method 3: GET /history (Requires API Key)
# ---------------------------------------------------------------------------
resource "aws_api_gateway_method" "get_history" {
  rest_api_id      = aws_api_gateway_rest_api.main.id
  resource_id      = aws_api_gateway_resource.history.id
  http_method      = "GET"
  authorization    = "NONE"
  api_key_required = true
}

resource "aws_api_gateway_integration" "get_history" {
  rest_api_id             = aws_api_gateway_rest_api.main.id
  resource_id             = aws_api_gateway_resource.history.id
  http_method             = aws_api_gateway_method.get_history.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = "arn:aws:apigateway:${data.aws_region.current.name}:lambda:path/2015-03-31/functions/${var.get_history_lambda_arn}/invocations"
}

data "aws_region" "current" {}

# ---------------------------------------------------------------------------
# CORS Configuration for API Endpoints (/scan, /scan/{id}, /history)
# OPTIONS methods must have authorization NONE and api_key_required = false
# ---------------------------------------------------------------------------

# 1. OPTIONS /scan
resource "aws_api_gateway_method" "options_scan" {
  rest_api_id      = aws_api_gateway_rest_api.main.id
  resource_id      = aws_api_gateway_resource.scan.id
  http_method      = "OPTIONS"
  authorization    = "NONE"
  api_key_required = false
}

resource "aws_api_gateway_integration" "options_scan" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  resource_id = aws_api_gateway_resource.scan.id
  http_method = aws_api_gateway_method.options_scan.http_method
  type        = "MOCK"

  request_templates = {
    "application/json" = "{\"statusCode\": 200}"
  }
}

resource "aws_api_gateway_method_response" "options_scan" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  resource_id = aws_api_gateway_resource.scan.id
  http_method = aws_api_gateway_method.options_scan.http_method
  status_code = "200"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = true
    "method.response.header.Access-Control-Allow-Methods" = true
    "method.response.header.Access-Control-Allow-Origin"  = true
  }

  response_models = {
    "application/json" = "Empty"
  }
}

resource "aws_api_gateway_integration_response" "options_scan" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  resource_id = aws_api_gateway_resource.scan.id
  http_method = aws_api_gateway_method.options_scan.http_method
  status_code = aws_api_gateway_method_response.options_scan.status_code

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = "'Content-Type,X-Api-Key'"
    "method.response.header.Access-Control-Allow-Methods" = "'OPTIONS,POST'"
    "method.response.header.Access-Control-Allow-Origin"  = "'*'"
  }

  depends_on = [
    aws_api_gateway_integration.options_scan,
    aws_api_gateway_method_response.options_scan,
  ]
}

# 2. OPTIONS /scan/{id}
resource "aws_api_gateway_method" "options_scan_id" {
  rest_api_id      = aws_api_gateway_rest_api.main.id
  resource_id      = aws_api_gateway_resource.scan_id.id
  http_method      = "OPTIONS"
  authorization    = "NONE"
  api_key_required = false
}

resource "aws_api_gateway_integration" "options_scan_id" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  resource_id = aws_api_gateway_resource.scan_id.id
  http_method = aws_api_gateway_method.options_scan_id.http_method
  type        = "MOCK"

  request_templates = {
    "application/json" = "{\"statusCode\": 200}"
  }
}

resource "aws_api_gateway_method_response" "options_scan_id" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  resource_id = aws_api_gateway_resource.scan_id.id
  http_method = aws_api_gateway_method.options_scan_id.http_method
  status_code = "200"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = true
    "method.response.header.Access-Control-Allow-Methods" = true
    "method.response.header.Access-Control-Allow-Origin"  = true
  }

  response_models = {
    "application/json" = "Empty"
  }
}

resource "aws_api_gateway_integration_response" "options_scan_id" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  resource_id = aws_api_gateway_resource.scan_id.id
  http_method = aws_api_gateway_method.options_scan_id.http_method
  status_code = aws_api_gateway_method_response.options_scan_id.status_code

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = "'Content-Type,X-Api-Key'"
    "method.response.header.Access-Control-Allow-Methods" = "'OPTIONS,GET'"
    "method.response.header.Access-Control-Allow-Origin"  = "'*'"
  }

  depends_on = [
    aws_api_gateway_integration.options_scan_id,
    aws_api_gateway_method_response.options_scan_id,
  ]
}

# 3. OPTIONS /history
resource "aws_api_gateway_method" "options_history" {
  rest_api_id      = aws_api_gateway_rest_api.main.id
  resource_id      = aws_api_gateway_resource.history.id
  http_method      = "OPTIONS"
  authorization    = "NONE"
  api_key_required = false
}

resource "aws_api_gateway_integration" "options_history" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  resource_id = aws_api_gateway_resource.history.id
  http_method = aws_api_gateway_method.options_history.http_method
  type        = "MOCK"

  request_templates = {
    "application/json" = "{\"statusCode\": 200}"
  }
}

resource "aws_api_gateway_method_response" "options_history" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  resource_id = aws_api_gateway_resource.history.id
  http_method = aws_api_gateway_method.options_history.http_method
  status_code = "200"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = true
    "method.response.header.Access-Control-Allow-Methods" = true
    "method.response.header.Access-Control-Allow-Origin"  = true
  }

  response_models = {
    "application/json" = "Empty"
  }
}

resource "aws_api_gateway_integration_response" "options_history" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  resource_id = aws_api_gateway_resource.history.id
  http_method = aws_api_gateway_method.options_history.http_method
  status_code = aws_api_gateway_method_response.options_history.status_code

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = "'Content-Type,X-Api-Key'"
    "method.response.header.Access-Control-Allow-Methods" = "'OPTIONS,GET'"
    "method.response.header.Access-Control-Allow-Origin"  = "'*'"
  }

  depends_on = [
    aws_api_gateway_integration.options_history,
    aws_api_gateway_method_response.options_history,
  ]
}

# ---------------------------------------------------------------------------
# Gateway Responses with CORS for 4XX and 5XX (so 403s etc. are browser-readable)
# ---------------------------------------------------------------------------
resource "aws_api_gateway_gateway_response" "default_4xx" {
  rest_api_id   = aws_api_gateway_rest_api.main.id
  response_type = "DEFAULT_4XX"

  response_parameters = {
    "gatewayresponse.header.Access-Control-Allow-Origin"  = "'*'"
    "gatewayresponse.header.Access-Control-Allow-Headers" = "'Content-Type,X-Api-Key'"
    "gatewayresponse.header.Access-Control-Allow-Methods" = "'GET,POST,OPTIONS'"
  }
}

resource "aws_api_gateway_gateway_response" "default_5xx" {
  rest_api_id   = aws_api_gateway_rest_api.main.id
  response_type = "DEFAULT_5XX"

  response_parameters = {
    "gatewayresponse.header.Access-Control-Allow-Origin"  = "'*'"
    "gatewayresponse.header.Access-Control-Allow-Headers" = "'Content-Type,X-Api-Key'"
    "gatewayresponse.header.Access-Control-Allow-Methods" = "'GET,POST,OPTIONS'"
  }
}

# ---------------------------------------------------------------------------
# Deployment & Stage
# ---------------------------------------------------------------------------
resource "aws_api_gateway_deployment" "main" {
  rest_api_id = aws_api_gateway_rest_api.main.id

  depends_on = [
    aws_api_gateway_integration.post_scan,
    aws_api_gateway_integration.get_scan,
    aws_api_gateway_integration.get_history,
    aws_api_gateway_integration.options_scan,
    aws_api_gateway_integration.options_scan_id,
    aws_api_gateway_integration.options_history,
    aws_api_gateway_integration_response.options_scan,
    aws_api_gateway_integration_response.options_scan_id,
    aws_api_gateway_integration_response.options_history,
    aws_api_gateway_gateway_response.default_4xx,
    aws_api_gateway_gateway_response.default_5xx,
  ]

  triggers = {
    redeployment = sha1(jsonencode([
      aws_api_gateway_resource.scan.id,
      aws_api_gateway_resource.scan_id.id,
      aws_api_gateway_resource.history.id,
      aws_api_gateway_method.post_scan.id,
      aws_api_gateway_method.get_scan.id,
      aws_api_gateway_method.get_history.id,
      aws_api_gateway_integration.post_scan.id,
      aws_api_gateway_integration.get_scan.id,
      aws_api_gateway_integration.get_history.id,
      aws_api_gateway_method.options_scan.id,
      aws_api_gateway_method.options_scan_id.id,
      aws_api_gateway_method.options_history.id,
      aws_api_gateway_integration.options_scan.id,
      aws_api_gateway_integration.options_scan_id,
      aws_api_gateway_integration.options_history.id,
      aws_api_gateway_integration_response.options_scan.id,
      aws_api_gateway_integration_response.options_scan_id,
      aws_api_gateway_integration_response.options_history.id,
      aws_api_gateway_gateway_response.default_4xx.id,
      aws_api_gateway_gateway_response.default_5xx.id,
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_api_gateway_stage" "v1" {
  deployment_id = aws_api_gateway_deployment.main.id
  rest_api_id   = aws_api_gateway_rest_api.main.id
  stage_name    = var.stage_name

  tags = var.tags
}

# ---------------------------------------------------------------------------
# API Key & Usage Plan with Rate Limiting
# ---------------------------------------------------------------------------
resource "aws_api_gateway_api_key" "main" {
  name        = "${var.project_name}-key"
  description = "Default client API key for ${var.project_name}"
  enabled     = true
  tags        = var.tags
}

resource "aws_api_gateway_usage_plan" "main" {
  name        = "${var.project_name}-usage-plan"
  description = "Usage plan with rate limit and monthly quota for ${var.project_name}"

  api_stages {
    api_id = aws_api_gateway_rest_api.main.id
    stage  = aws_api_gateway_stage.v1.stage_name
  }

  throttle_settings {
    rate_limit  = var.rate_limit
    burst_limit = var.burst_limit
  }

  quota_settings {
    limit  = var.quota_limit
    period = "MONTH"
  }

  tags = var.tags
}

resource "aws_api_gateway_usage_plan_key" "main" {
  key_id        = aws_api_gateway_api_key.main.id
  key_type      = "API_KEY"
  usage_plan_id = aws_api_gateway_usage_plan.main.id
}

# ---------------------------------------------------------------------------
# Lambda Permissions for API Gateway
# ---------------------------------------------------------------------------
resource "aws_lambda_permission" "post_scan" {
  statement_id  = "AllowAPIGatewayInvokePostScan"
  action        = "lambda:InvokeFunction"
  function_name = var.post_scan_function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.main.execution_arn}/*/*"
}

resource "aws_lambda_permission" "get_scan" {
  statement_id  = "AllowAPIGatewayInvokeGetScan"
  action        = "lambda:InvokeFunction"
  function_name = var.get_scan_function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.main.execution_arn}/*/*"
}

resource "aws_lambda_permission" "get_history" {
  statement_id  = "AllowAPIGatewayInvokeGetHistory"
  action        = "lambda:InvokeFunction"
  function_name = var.get_history_function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.main.execution_arn}/*/*"
}
