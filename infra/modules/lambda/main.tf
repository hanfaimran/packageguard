# ---------------------------------------------------------------------------
# Common Trust Policy for Lambda Service Roles
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

# ---------------------------------------------------------------------------
# 1. POST /scan Lambda (post-scan)
# Role needs: S3 PutObject, DynamoDB PutItem, KMS GenerateDataKey/Encrypt, CloudWatch Logs
# ---------------------------------------------------------------------------
resource "aws_iam_role" "post_scan" {
  name               = "${var.project_name}-post-scan-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
  tags               = var.tags
}

resource "aws_iam_policy" "post_scan" {
  name        = "${var.project_name}-post-scan-policy"
  description = "Least privilege policy for post-scan Lambda"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${var.reports_bucket_arn}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem"]
        Resource = var.scans_table_arn
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:GenerateDataKey*"
        ]
        Resource = var.kms_key_arn
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.post_scan.arn}:*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "post_scan" {
  role       = aws_iam_role.post_scan.name
  policy_arn = aws_iam_policy.post_scan.arn
}

resource "aws_cloudwatch_log_group" "post_scan" {
  name              = "/aws/lambda/${var.project_name}-post-scan"
  retention_in_days = 14
  tags              = var.tags
}

resource "aws_lambda_function" "post_scan" {
  function_name = "${var.project_name}-post-scan"
  filename      = "${var.lambda_zip_dir}/post-scan.zip"
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  role          = aws_iam_role.post_scan.arn
  timeout       = 60
  memory_size   = 1024

  environment {
    variables = {
      SCANS_TABLE_NAME    = var.scans_table_name
      REPORTS_BUCKET_NAME = var.reports_bucket_name
      NPM_REGISTRY_URL    = var.npm_registry_url
    }
  }

  depends_on = [aws_cloudwatch_log_group.post_scan]
  tags       = var.tags
}

# ---------------------------------------------------------------------------
# 2. GET /scan/{id} Lambda (get-scan)
# Role needs: DynamoDB GetItem, S3 GetObject, KMS Decrypt, CloudWatch Logs
# ---------------------------------------------------------------------------
resource "aws_iam_role" "get_scan" {
  name               = "${var.project_name}-get-scan-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
  tags               = var.tags
}

resource "aws_iam_policy" "get_scan" {
  name        = "${var.project_name}-get-scan-policy"
  description = "Least privilege policy for get-scan Lambda"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem"]
        Resource = var.scans_table_arn
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "${var.reports_bucket_arn}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = var.kms_key_arn
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.get_scan.arn}:*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "get_scan" {
  role       = aws_iam_role.get_scan.name
  policy_arn = aws_iam_policy.get_scan.arn
}

resource "aws_cloudwatch_log_group" "get_scan" {
  name              = "/aws/lambda/${var.project_name}-get-scan"
  retention_in_days = 14
  tags              = var.tags
}

resource "aws_lambda_function" "get_scan" {
  function_name = "${var.project_name}-get-scan"
  filename      = "${var.lambda_zip_dir}/get-scan.zip"
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  role          = aws_iam_role.get_scan.arn
  timeout       = 30
  memory_size   = 512

  environment {
    variables = {
      SCANS_TABLE_NAME    = var.scans_table_name
      REPORTS_BUCKET_NAME = var.reports_bucket_name
    }
  }

  depends_on = [aws_cloudwatch_log_group.get_scan]
  tags       = var.tags
}

# ---------------------------------------------------------------------------
# 3. GET /history Lambda (get-history)
# Role needs: DynamoDB Query on Scans table and PackageIndex, KMS Decrypt, CloudWatch Logs
# ---------------------------------------------------------------------------
resource "aws_iam_role" "get_history" {
  name               = "${var.project_name}-get-history-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
  tags               = var.tags
}

resource "aws_iam_policy" "get_history" {
  name        = "${var.project_name}-get-history-policy"
  description = "Least privilege policy for get-history Lambda"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["dynamodb:Query"]
        Resource = [
          var.scans_table_arn,
          "${var.scans_table_arn}/index/PackageIndex"
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = var.kms_key_arn
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.get_history.arn}:*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "get_history" {
  role       = aws_iam_role.get_history.name
  policy_arn = aws_iam_policy.get_history.arn
}

resource "aws_cloudwatch_log_group" "get_history" {
  name              = "/aws/lambda/${var.project_name}-get-history"
  retention_in_days = 14
  tags              = var.tags
}

resource "aws_lambda_function" "get_history" {
  function_name = "${var.project_name}-get-history"
  filename      = "${var.lambda_zip_dir}/get-history.zip"
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  role          = aws_iam_role.get_history.arn
  timeout       = 30
  memory_size   = 512

  environment {
    variables = {
      SCANS_TABLE_NAME = var.scans_table_name
    }
  }

  depends_on = [aws_cloudwatch_log_group.get_history]
  tags       = var.tags
}

# ---------------------------------------------------------------------------
# 4. Nightly Rescan Scheduled Lambda (nightly-rescan)
# Role needs: DynamoDB Scan/PutItem on Watchlist, PutItem on Scans, S3 PutObject,
# SNS Publish on Alerts topic, KMS Encrypt/Decrypt, CloudWatch Logs
# ---------------------------------------------------------------------------
resource "aws_iam_role" "nightly_rescan" {
  name               = "${var.project_name}-nightly-rescan-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
  tags               = var.tags
}

resource "aws_iam_policy" "nightly_rescan" {
  name        = "${var.project_name}-nightly-rescan-policy"
  description = "Least privilege policy for nightly-rescan Lambda"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:Scan",
          "dynamodb:PutItem",
          "dynamodb:GetItem"
        ]
        Resource = var.watchlist_table_arn
      },
      {
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem"]
        Resource = var.scans_table_arn
      },
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${var.reports_bucket_arn}/*"
      },
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = var.alerts_topic_arn
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey*"
        ]
        Resource = var.kms_key_arn
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.nightly_rescan.arn}:*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "nightly_rescan" {
  role       = aws_iam_role.nightly_rescan.name
  policy_arn = aws_iam_policy.nightly_rescan.arn
}

resource "aws_cloudwatch_log_group" "nightly_rescan" {
  name              = "/aws/lambda/${var.project_name}-nightly-rescan"
  retention_in_days = 14
  tags              = var.tags
}

resource "aws_lambda_function" "nightly_rescan" {
  function_name = "${var.project_name}-nightly-rescan"
  filename      = "${var.lambda_zip_dir}/nightly-rescan.zip"
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  role          = aws_iam_role.nightly_rescan.arn
  timeout       = 300
  memory_size   = 1024

  environment {
    variables = {
      SCANS_TABLE_NAME     = var.scans_table_name
      WATCHLIST_TABLE_NAME = var.watchlist_table_name
      REPORTS_BUCKET_NAME  = var.reports_bucket_name
      ALERTS_TOPIC_ARN     = var.alerts_topic_arn
      NPM_REGISTRY_URL     = var.npm_registry_url
    }
  }

  depends_on = [aws_cloudwatch_log_group.nightly_rescan]
  tags       = var.tags
}
