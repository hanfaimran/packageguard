# ---------------------------------------------------------------------------
# S3 Bucket for Full Reports
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "reports" {
  bucket        = "${var.project_name}-reports-${data.aws_caller_identity.current.account_id}"
  force_destroy = false

  tags = merge(var.tags, {
    Name = "${var.project_name}-reports"
  })
}

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket_versioning" "reports" {
  bucket = aws_s3_bucket.reports.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.kms_key_arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket = aws_s3_bucket.reports.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ---------------------------------------------------------------------------
# DynamoDB Scans Table (Scan results metadata)
# ---------------------------------------------------------------------------
resource "aws_dynamodb_table" "scans" {
  name         = "${var.project_name}-scans"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  attribute {
    name = "package"
    type = "S"
  }

  attribute {
    name = "scannedAt"
    type = "S"
  }

  global_secondary_index {
    name            = "PackageIndex"
    hash_key        = "package"
    range_key       = "scannedAt"
    projection_type = "ALL"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-scans"
  })
}

# ---------------------------------------------------------------------------
# DynamoDB Watchlist Table (Packages monitored nightly)
# ---------------------------------------------------------------------------
resource "aws_dynamodb_table" "watchlist" {
  name         = "${var.project_name}-watchlist"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "package"
  range_key    = "version"

  attribute {
    name = "package"
    type = "S"
  }

  attribute {
    name = "version"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = var.kms_key_arn
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-watchlist"
  })
}
