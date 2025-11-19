# ============================================================================
# SNS Topics for Security & Compliance Alerts
# ============================================================================

# ============================================================================
# Security Alerts Topic (Critical & High Severity)
# ============================================================================

resource "aws_sns_topic" "security_alerts" {
  name              = local.security_alerts_topic
  display_name      = "Security Alerts - Critical & High Severity"
  kms_master_key_id = aws_kms_key.secrets.id

  tags = merge(
    local.security_tags,
    {
      Name = "${local.name_prefix}-security-alerts"
    }
  )
}

resource "aws_sns_topic_policy" "security_alerts" {
  arn = aws_sns_topic.security_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudWatchEvents"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action   = "SNS:Publish"
        Resource = aws_sns_topic.security_alerts.arn
      },
      {
        Sid    = "AllowCloudWatchAlarms"
        Effect = "Allow"
        Principal = {
          Service = "cloudwatch.amazonaws.com"
        }
        Action   = "SNS:Publish"
        Resource = aws_sns_topic.security_alerts.arn
      },
      {
        Sid    = "AllowGuardDuty"
        Effect = "Allow"
        Principal = {
          Service = "guardduty.amazonaws.com"
        }
        Action   = "SNS:Publish"
        Resource = aws_sns_topic.security_alerts.arn
      }
    ]
  })
}

resource "aws_sns_topic_subscription" "security_alerts_email" {
  count     = var.alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ============================================================================
# Compliance Alerts Topic
# ============================================================================

resource "aws_sns_topic" "compliance_alerts" {
  name              = local.compliance_alerts_topic
  display_name      = "Compliance Alerts - Config & Policy Violations"
  kms_master_key_id = aws_kms_key.secrets.id

  tags = merge(
    local.security_tags,
    {
      Name = "${local.name_prefix}-compliance-alerts"
    }
  )
}

resource "aws_sns_topic_policy" "compliance_alerts" {
  arn = aws_sns_topic.compliance_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudWatchEvents"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action   = "SNS:Publish"
        Resource = aws_sns_topic.compliance_alerts.arn
      },
      {
        Sid    = "AllowConfigService"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "SNS:Publish"
        Resource = aws_sns_topic.compliance_alerts.arn
      },
      {
        Sid    = "AllowSecurityHub"
        Effect = "Allow"
        Principal = {
          Service = "securityhub.amazonaws.com"
        }
        Action   = "SNS:Publish"
        Resource = aws_sns_topic.compliance_alerts.arn
      }
    ]
  })
}

resource "aws_sns_topic_subscription" "compliance_alerts_email" {
  count     = var.alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.compliance_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ============================================================================
# Medium Priority Alerts Topic (Optional)
# ============================================================================

resource "aws_sns_topic" "medium_alerts" {
  count             = var.enable_medium_alerts ? 1 : 0
  name              = "${local.name_prefix}-medium-alerts"
  display_name      = "Medium Priority Security Alerts"
  kms_master_key_id = aws_kms_key.secrets.id

  tags = merge(
    local.security_tags,
    {
      Name = "${local.name_prefix}-medium-alerts"
    }
  )
}

resource "aws_sns_topic_subscription" "medium_alerts_email" {
  count     = var.enable_medium_alerts && var.alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.medium_alerts[0].arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ============================================================================
# Slack Integration (Optional)
# ============================================================================

# Uncomment if using Slack webhook
# resource "aws_sns_topic_subscription" "security_alerts_slack" {
#   count     = var.slack_webhook_url != "" ? 1 : 0
#   topic_arn = aws_sns_topic.security_alerts.arn
#   protocol  = "https"
#   endpoint  = var.slack_webhook_url
# }

# ============================================================================
# Lambda Function for Custom Alert Formatting (Optional)
# ============================================================================

# Example: Lambda to format and forward alerts to Slack
# data "archive_file" "alert_lambda" {
#   type        = "zip"
#   source_file = "${path.module}/../lambda/alert_formatter.py"
#   output_path = "${path.module}/../lambda/alert_formatter.zip"
# }

# resource "aws_lambda_function" "alert_formatter" {
#   filename         = data.archive_file.alert_lambda.output_path
#   function_name    = "${local.name_prefix}-alert-formatter"
#   role            = aws_iam_role.remediation_lambda.arn
#   handler         = "alert_formatter.lambda_handler"
#   source_code_hash = data.archive_file.alert_lambda.output_base64sha256
#   runtime         = "python3.9"
#   timeout         = 30
#
#   environment {
#     variables = {
#       SLACK_WEBHOOK = var.slack_webhook_url
#     }
#   }
#
#   tags = local.security_tags
# }

# resource "aws_sns_topic_subscription" "security_alerts_lambda" {
#   topic_arn = aws_sns_topic.security_alerts.arn
#   protocol  = "lambda"
#   endpoint  = aws_lambda_function.alert_formatter.arn
# }

# resource "aws_lambda_permission" "sns_invoke" {
#   statement_id  = "AllowExecutionFromSNS"
#   action        = "lambda:InvokeFunction"
#   function_name = aws_lambda_function.alert_formatter.function_name
#   principal     = "sns.amazonaws.com"
#   source_arn    = aws_sns_topic.security_alerts.arn
# }

# ============================================================================
# Outputs
# ============================================================================

output "security_alerts_topic_arn" {
  description = "ARN of the security alerts SNS topic"
  value       = aws_sns_topic.security_alerts.arn
}

output "compliance_alerts_topic_arn" {
  description = "ARN of the compliance alerts SNS topic"
  value       = aws_sns_topic.compliance_alerts.arn
}

output "alert_email" {
  description = "Email address receiving alerts"
  value       = var.alert_email
  sensitive   = true
}