# ---------------------------------------------------------------------------
# EventBridge Nightly Rule (Cron trigger at 02:00 UTC every night)
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "nightly" {
  name                = "${var.project_name}-nightly-rescan-rule"
  description         = "Triggers PackageGuard nightly watchlist re-scan"
  schedule_expression = "cron(0 2 * * ? *)"

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "nightly" {
  rule      = aws_cloudwatch_event_rule.nightly.name
  target_id = "NightlyRescanLambdaTarget"
  arn       = var.nightly_rescan_lambda_arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowEventBridgeInvokeNightlyRescan"
  action        = "lambda:InvokeFunction"
  function_name = var.nightly_rescan_function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.nightly.arn
}

# ---------------------------------------------------------------------------
# CloudWatch Error-Rate Alarms for Lambda Functions
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  for_each = toset(var.lambda_function_names)

  alarm_name          = "${each.value}-error-rate-alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Triggers when function ${each.value} encounters 1 or more errors in 5 minutes"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = each.value
  }

  alarm_actions = [var.alerts_topic_arn]
  ok_actions    = [var.alerts_topic_arn]

  tags = var.tags
}
