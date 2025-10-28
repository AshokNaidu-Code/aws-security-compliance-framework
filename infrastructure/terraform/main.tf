# KMS Module for Encryption
module "kms" {
  source = "../modules/kms"

  environment     = var.environment
  key_description = "KMS key for security compliance encryption"
}

# IAM Module with MFA Enforcement
module "iam" {
  source = "../modules/iam"

  environment            = var.environment
  enable_mfa_enforcement = var.enable_mfa_enforcement
  kms_key_arn            = module.kms.key_arn
}

# GuardDuty Module
module "guardduty" {
  source = "../modules/guardduty"

  environment                  = var.environment
  finding_publishing_frequency = var.guardduty_finding_publishing_frequency
  enable_s3_protection         = var.enable_s3_protection
  enable_kubernetes_protection = var.enable_kubernetes_protection
  kms_key_arn                  = module.kms.key_arn
  sns_topic_arn                = aws_sns_topic.security_alerts.arn
}

# AWS Config Module
module "config" {
  source = "../modules/config"

  environment          = var.environment
  config_recorder_name = var.config_recorder_name
  s3_bucket_name       = aws_s3_bucket.config_bucket.id
  kms_key_arn          = module.kms.key_arn
  sns_topic_arn        = aws_sns_topic.security_alerts.arn
}

# CloudTrail Module
module "cloudtrail" {
  source = "../modules/cloudtrail"

  environment           = var.environment
  s3_bucket_name        = var.cloudtrail_s3_bucket_name
  kms_key_arn           = module.kms.key_arn
  enable_log_validation = true
}

# S3 Bucket for AWS Config
resource "aws_s3_bucket" "config_bucket" {
  bucket = "${var.environment}-aws-config-logs-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config_bucket" {
  bucket = aws_s3_bucket.config_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = module.kms.key_arn
    }
  }
}

resource "aws_s3_bucket_versioning" "config_bucket" {
  bucket = aws_s3_bucket.config_bucket.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "config_bucket" {
  bucket = aws_s3_bucket.config_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# SNS Topic for Security Alerts
resource "aws_sns_topic" "security_alerts" {
  name              = "${var.environment}-security-alerts"
  kms_master_key_id = module.kms.key_arn
}

resource "aws_sns_topic_subscription" "email_subscriptions" {
  count     = length(var.sns_email_endpoints)
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.sns_email_endpoints[count.index]
}

# EventBridge Rule for GuardDuty Findings
resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name        = "${var.environment}-guardduty-findings"
  description = "Capture GuardDuty findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [7, 8, 9] # High and Critical findings
    }
  })
}

resource "aws_cloudwatch_event_target" "guardduty_to_sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_findings.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.security_alerts.arn
}

# Lambda for GuardDuty Response
resource "aws_lambda_function" "guardduty_response" {
  filename      = "${path.module}/../../automation/lambda/guardduty_findings_processor.zip"
  function_name = "${var.environment}-guardduty-response"
  role          = aws_iam_role.lambda_guardduty_response.arn
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.11"
  timeout       = 300
  kms_key_arn   = module.kms.key_arn

  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.security_alerts.arn
      ENVIRONMENT   = var.environment
    }
  }
}

resource "aws_iam_role" "lambda_guardduty_response" {
  name = "${var.environment}-lambda-guardduty-response"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  role       = aws_iam_role.lambda_guardduty_response.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "lambda_guardduty_policy" {
  name = "${var.environment}-lambda-guardduty-policy"
  role = aws_iam_role.lambda_guardduty_response.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "guardduty:GetFindings",
          "guardduty:ListFindings",
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups",
          "ec2:RevokeSecurityGroupIngress",
          "sns:Publish"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_cloudwatch_event_target" "guardduty_to_lambda" {
  rule      = aws_cloudwatch_event_rule.guardduty_findings.name
  target_id = "InvokeLambda"
  arn       = aws_lambda_function.guardduty_response.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.guardduty_response.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_findings.arn
}

data "aws_caller_identity" "current" {}
