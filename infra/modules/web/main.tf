data "aws_caller_identity" "current" {}

# ---------------------------------------------------------------------------
# S3 Bucket for Hosted Web Dashboard (SSE-S3, Private, All Public Access Blocked)
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "web" {
  bucket        = "${var.project_name}-web-${data.aws_caller_identity.current.account_id}"
  force_destroy = true

  tags = merge(var.tags, {
    Name = "${var.project_name}-web"
  })
}

resource "aws_s3_bucket_server_side_encryption_configuration" "web" {
  bucket = aws_s3_bucket.web.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "web" {
  bucket = aws_s3_bucket.web.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ---------------------------------------------------------------------------
# CloudFront Origin Access Control (OAC)
# ---------------------------------------------------------------------------
resource "aws_cloudfront_origin_access_control" "web" {
  name                              = "${var.project_name}-web-oac"
  description                       = "OAC for ${var.project_name} static web dashboard"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# ---------------------------------------------------------------------------
# CloudFront Distribution
# ---------------------------------------------------------------------------
resource "aws_cloudfront_distribution" "web" {
  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = "index.html"
  comment             = "${var.project_name} Web Dashboard"

  origin {
    domain_name              = aws_s3_bucket.web.bucket_regional_domain_name
    origin_id                = "S3-${aws_s3_bucket.web.id}"
    origin_access_control_id = aws_cloudfront_origin_access_control.web.id
  }

  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "S3-${aws_s3_bucket.web.id}"

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "redirect-to-https"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-web-distribution"
  })
}

# ---------------------------------------------------------------------------
# S3 Bucket Policy: Allowing ONLY the CloudFront distribution via OAC
# ---------------------------------------------------------------------------
resource "aws_s3_bucket_policy" "web" {
  bucket = aws_s3_bucket.web.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowCloudFrontServicePrincipal"
        Effect    = "Allow"
        Principal = {
          Service = "cloudfront.amazonaws.com"
        }
        Action   = "s3:GetObject"
        Resource = "${aws_s3_bucket.web.arn}/*"
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = aws_cloudfront_distribution.web.arn
          }
        }
      }
    ]
  })
}

# ---------------------------------------------------------------------------
# Static Site Object Uploads
# ---------------------------------------------------------------------------
resource "aws_s3_object" "index_html" {
  bucket       = aws_s3_bucket.web.id
  key          = "index.html"
  source       = var.index_html_path
  content_type = "text/html; charset=utf-8"
  etag         = filemd5(var.index_html_path)
}

resource "aws_s3_object" "config_js" {
  bucket       = aws_s3_bucket.web.id
  key          = "config.js"
  content      = <<-EOT
window.PG_CONFIG = {
  API_URL: "${var.api_invoke_url}",
  API_KEY: "${var.api_key_value}"
};
EOT
  content_type = "application/javascript; charset=utf-8"
  etag         = md5("window.PG_CONFIG = { API_URL: \"${var.api_invoke_url}\", API_KEY: \"${var.api_key_value}\" };")
}
