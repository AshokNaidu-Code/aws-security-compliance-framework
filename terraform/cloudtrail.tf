# ============================================================================
# AWS CloudTrail - Comprehensive Audit Logging
# ============================================================================

# ============================================================================
# CloudWatch Log Group for CloudTrail
# ============================================================================

resource "aws_cloudwatch_log_group" "cloudtrail" {
  count = var.enable_cloudtrail ? 1 : 0

  name              = "/aws/cloudtrail/${local.name_prefix}"
  retention_in_days = var.cloudtrail_log_retention
  kms_key_id        = aws_kms_key.cloudtrail[0].arn

  tags = merge(
    local.security_tags,
    {
      Name = "${local.name_prefix}-cloudtrail-logs"
    }
  )
}

# ============================================================================
# CloudTrail - Multi-Region Trail
# ============================================================================

resource "aws_cloudtrail" "main" {
  count = var.enable_cloudtrail ? 1 : 0

  name                          = "${local.name_prefix}-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail[0].id
  include_global_service_events = true
  is_multi_region_trail         = true
  is_organization_trail         = false
  enable_logging                = true
  enable_log_file_validation    = true

  # KMS encryption
  kms_key_id = aws_kms_key.cloudtrail[0].arn

  # CloudWatch Logs integration
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail[0].arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail.arn

  # Event selectors for S3 and Lambda data events
  event_selector {
    read_write_type           = "All"
    include_management_events = true

    # Log S3 data events
    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:${local.partition}:s3:::*/*"]
    }

    # Log Lambda function invocations
    data_resource {
      type   = "AWS::Lambda::Function"
      values = ["arn:${local.partition}:lambda:*:${local.account_id}:function/*"]
    }
  }

  # Insight selectors for anomaly detection
  insight_selector {
    insight_type = "ApiCallRateInsight"
  }

  tags = merge(
    local.security_tags,
    {
      Name = "${local.name_prefix}-cloudtrail"
    }
  )

  depends_on = [
    aws_s3_bucket_policy.cloudtrail
  ]
}

# ============================================================================
# CloudWatch Metric Filters & Alarms for CIS Benchmarks
# ============================================================================

# CIS 3.1 - Unauthorized API calls
resource "aws_cloudwatch_log_metric_filter" "unauthorized_api_calls" {
  count = var.enable_cloudtrail ? 1 : 0

  name           = "${local.name_prefix}-unauthorized-api-calls"
  log_group_name = aws_cloudwatch_log_group.cloudtrail[0].name

  pattern = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"

  metric_transformation {
    name      = "UnauthorizedAPICalls"
    namespace = "${local.name_prefix}/CloudTrail"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "unauthorized_api_calls" {
  count = var.enable_cloudtrail ? 1 : 0

  alarm_name          = "${local.name_prefix}-unauthorized-api-calls"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "UnauthorizedAPICalls"
  namespace           = "${local.name_prefix}/CloudTrail"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "Triggers when unauthorized API calls are detected"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  treat_missing_data  = "notBreaching"

  tags = local.security_tags
}

# CIS 3.2 - Root account usage
resource "aws_cloudwatch_log_metric_filter" "root_usage" {
  count = var.enable_cloudtrail ? 1 : 0

  name           = "${local.name_prefix}-root-usage"
  log_group_name = aws_cloudwatch_log_group.cloudtrail[0].name

  pattern = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"

  metric_transformation {
    name      = "RootAccountUsage"
    namespace = "${local.name_prefix}/CloudTrail"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "root_usage" {
  count = var.enable_cloudtrail ? 1 : 0

  alarm_name          = "${local.name_prefix}-root-account-usage"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "RootAccountUsage"
  namespace           = "${local.name_prefix}/CloudTrail"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "Triggers when root account is used"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  treat_missing_data  = "notBreaching"

  tags = local.security_tags
}

# CIS 3.3 - IAM policy changes
resource "aws_cloudwatch_log_metric_filter" "iam_policy_changes" {
  count = var.enable_cloudtrail ? 1 : 0

  name           = "${local.name_prefix}-iam-policy-changes"
  log_group_name = aws_cloudwatch_log_group.cloudtrail[0].name

  pattern = "{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}"

  metric_transformation {
    name      = "IAMPolicyChanges"
    namespace = "${local.name_prefix}/CloudTrail"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "iam_policy_changes" {
  count = var.enable_cloudtrail ? 1 : 0

  alarm_name          = "${local.name_prefix}-iam-policy-changes"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "IAMPolicyChanges"
  namespace           = "${local.name_prefix}/CloudTrail"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "Triggers when IAM policy changes are detected"
  alarm_actions       = [aws_sns_topic.compliance_alerts.arn]
  treat_missing_data  = "notBreaching"

  tags = local.security_tags
}

# CIS 3.4 - CloudTrail configuration changes
resource "aws_cloudwatch_log_metric_filter" "cloudtrail_changes" {
  count = var.enable_cloudtrail ? 1 : 0

  name           = "${local.name_prefix}-cloudtrail-changes"
  log_group_name = aws_cloudwatch_log_group.cloudtrail[0].name

  pattern = "{($.eventName=CreateTrail)||($.eventName=UpdateTrail)||($.eventName=DeleteTrail)||($.eventName=StartLogging)||($.eventName=StopLogging)}"

  metric_transformation {
    name      = "CloudTrailChanges"
    namespace = "${local.name_prefix}/CloudTrail"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cloudtrail_changes" {
  count = var.enable_cloudtrail ? 1 : 0

  alarm_name          = "${local.name_prefix}-cloudtrail-changes"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "CloudTrailChanges"
  namespace           = "${local.name_prefix}/CloudTrail"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "Triggers when CloudTrail configuration is changed"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  treat_missing_data  = "notBreaching"

  tags = local.security_tags
}

# CIS 3.5 - Console sign-in failures
resource "aws_cloudwatch_log_metric_filter" "console_signin_failures" {
  count = var.enable_cloudtrail ? 1 : 0

  name           = "${local.name_prefix}-console-signin-failures"
  log_group_name = aws_cloudwatch_log_group.cloudtrail[0].name

  pattern = "{ ($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\") }"

  metric_transformation {
    name      = "ConsoleSignInFailures"
    namespace = "${local.name_prefix}/CloudTrail"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "console_signin_failures" {
  count = var.enable_cloudtrail ? 1 : 0

  alarm_name          = "${local.name_prefix}-console-signin-failures"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "ConsoleSignInFailures"
  namespace           = "${local.name_prefix}/CloudTrail"
  period              = "300"
  statistic           = "Sum"
  threshold           = "3"
  alarm_description   = "Triggers when 3 or more console sign-in failures occur"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  treat_missing_data  = "notBreaching"

  tags = local.security_tags
}

# CIS 3.6 - Disabling or deleting CMK
resource "aws_cloudwatch_log_metric_filter" "cmk_changes" {
  count = var.enable_cloudtrail ? 1 : 0

  name           = "${local.name_prefix}-cmk-changes"
  log_group_name = aws_cloudwatch_log_group.cloudtrail[0].name

  pattern = "{($.eventSource=kms.amazonaws.com) && (($.eventName=DisableKey)||($.eventName=ScheduleKeyDeletion))}"

  metric_transformation {
    name      = "CMKChanges"
    namespace = "${local.name_prefix}/CloudTrail"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cmk_changes" {
  count = var.enable_cloudtrail ? 1 : 0

  alarm_name          = "${local.name_prefix}-cmk-changes"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "CMKChanges"
  namespace           = "${local.name_prefix}/CloudTrail"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "Triggers when KMS keys are disabled or scheduled for deletion"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  treat_missing_data  = "notBreaching"

  tags = local.security_tags
}

# CIS 3.7 - S3 bucket policy changes
resource "aws_cloudwatch_log_metric_filter" "s3_bucket_policy_changes" {
  count = var.enable_cloudtrail ? 1 : 0

  name           = "${local.name_prefix}-s3-bucket-policy-changes"
  log_group_name = aws_cloudwatch_log_group.cloudtrail[0].name

  pattern = "{($.eventSource=s3.amazonaws.com) && (($.eventName=PutBucketAcl)||($.eventName=PutBucketPolicy)||($.eventName=PutBucketCors)||($.eventName=PutBucketLifecycle)||($.eventName=PutBucketReplication)||($.eventName=DeleteBucketPolicy)||($.eventName=DeleteBucketCors)||($.eventName=DeleteBucketLifecycle)||($.eventName=DeleteBucketReplication))}"

  metric_transformation {
    name      = "S3BucketPolicyChanges"
    namespace = "${local.name_prefix}/CloudTrail"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "s3_bucket_policy_changes" {
  count = var.enable_cloudtrail ? 1 : 0

  alarm_name          = "${local.name_prefix}-s3-bucket-policy-changes"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "S3BucketPolicyChanges"
  namespace           = "${local.name_prefix}/CloudTrail"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "Triggers when S3 bucket policies are changed"
  alarm_actions       = [aws_sns_topic.compliance_alerts.arn]
  treat_missing_data  = "notBreaching"

  tags = local.security_tags
}

# CIS 3.8 - Security group changes
resource "aws_cloudwatch_log_metric_filter" "security_group_changes" {
  count = var.enable_cloudtrail ? 1 : 0

  name           = "${local.name_prefix}-security-group-changes"
  log_group_name = aws_cloudwatch_log_group.cloudtrail[0].name

  pattern = "{($.eventName=AuthorizeSecurityGroupIngress)||($.eventName=AuthorizeSecurityGroupEgress)||($.eventName=RevokeSecurityGroupIngress)||($.eventName=RevokeSecurityGroupEgress)||($.eventName=CreateSecurityGroup)||($.eventName=DeleteSecurityGroup)}"

  metric_transformation {
    name      = "SecurityGroupChanges"
    namespace = "${local.name_prefix}/CloudTrail"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "security_group_changes" {
  count = var.enable_cloudtrail ? 1 : 0

  alarm_name          = "${local.name_prefix}-security-group-changes"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "SecurityGroupChanges"
  namespace           = "${local.name_prefix}/CloudTrail"
  period              = "300"
  statistic           = "Sum"
  threshold           = "1"
  alarm_description   = "Triggers when security groups are modified"
  alarm_actions       = [aws_sns_topic.compliance_alerts.arn]
  treat_missing_data  = "notBreaching"

  tags = local.security_tags
}

