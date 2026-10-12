provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

locals {
  common_tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

# ---------------------------------------------------------------------------
# 1. KMS Module (Customer Managed Key with rotation)
# ---------------------------------------------------------------------------
module "kms" {
  source = "./modules/kms"

  project_name = var.project_name
  tags         = local.common_tags
}

# ---------------------------------------------------------------------------
# 2. Storage Module (DynamoDB Scans & Watchlist, S3 Reports Bucket)
# ---------------------------------------------------------------------------
module "storage" {
  source = "./modules/storage"

  project_name = var.project_name
  kms_key_arn  = module.kms.key_arn
  tags         = local.common_tags
}

# ---------------------------------------------------------------------------
# 3. SNS Alerts Topic
# ---------------------------------------------------------------------------
resource "aws_sns_topic" "alerts" {
  name              = "${var.project_name}-alerts"
  kms_master_key_id = module.kms.key_arn

  tags = merge(local.common_tags, {
    Name = "${var.project_name}-alerts"
  })
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ---------------------------------------------------------------------------
# 4. Lambda Module (4 functions with least privilege roles & 14-day logs)
# ---------------------------------------------------------------------------
module "lambda" {
  source = "./modules/lambda"

  project_name         = var.project_name
  lambda_zip_dir       = "${path.root}/build"
  scans_table_name     = module.storage.scans_table_name
  scans_table_arn      = module.storage.scans_table_arn
  watchlist_table_name = module.storage.watchlist_table_name
  watchlist_table_arn  = module.storage.watchlist_table_arn
  reports_bucket_name  = module.storage.reports_bucket_name
  reports_bucket_arn   = module.storage.reports_bucket_arn
  alerts_topic_arn     = aws_sns_topic.alerts.arn
  kms_key_arn          = module.kms.key_arn
  npm_registry_url     = var.npm_registry_url
  tags                 = local.common_tags
}

# ---------------------------------------------------------------------------
# 5. Alerts Module (EventBridge Nightly Rule & CloudWatch Error Alarms)
# ---------------------------------------------------------------------------
module "alerts" {
  source = "./modules/alerts"

  project_name                 = var.project_name
  alerts_topic_arn             = aws_sns_topic.alerts.arn
  nightly_rescan_lambda_arn    = module.lambda.nightly_rescan_arn
  nightly_rescan_function_name = module.lambda.nightly_rescan_function_name
  lambda_function_names = [
    module.lambda.post_scan_function_name,
    module.lambda.get_scan_function_name,
    module.lambda.get_history_function_name,
    module.lambda.nightly_rescan_function_name,
  ]
  tags = local.common_tags
}

# ---------------------------------------------------------------------------
# 5. API Gateway Module (REST API, API key, Usage Plan, Rate Limits, Routes)
# ---------------------------------------------------------------------------
module "api" {
  source = "./modules/api"

  project_name             = var.project_name
  stage_name               = "v1"
  post_scan_lambda_arn     = module.lambda.post_scan_arn
  post_scan_function_name  = module.lambda.post_scan_function_name
  get_scan_lambda_arn      = module.lambda.get_scan_arn
  get_scan_function_name   = module.lambda.get_scan_function_name
  get_history_lambda_arn   = module.lambda.get_history_arn
  get_history_function_name = module.lambda.get_history_function_name
  tags                     = local.common_tags
}
