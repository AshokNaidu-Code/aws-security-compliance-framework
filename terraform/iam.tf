# ============================================================================
# IAM Security Controls & Password Policy
# ============================================================================

# ============================================================================
# Account Password Policy (CIS 1.5-1.11)
# ============================================================================

resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = var.password_minimum_length
  require_lowercase_characters   = var.require_lowercase
  require_uppercase_characters   = var.require_uppercase
  require_numbers                = var.require_numbers
  require_symbols                = var.require_symbols
  allow_users_to_change_password = true
  max_password_age              = var.password_max_age
  password_reuse_prevention     = var.password_reuse_prevention
  hard_expiry                   = false
}

# ============================================================================
# Security Audit Role (for security team)
# ============================================================================

resource "aws_iam_role" "security_audit" {
  name        = "${local.name_prefix}-security-audit-role"
  description = "Role for security auditing and compliance checking"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:${local.partition}:iam::${local.account_id}:root"
        }
        Action = "sts:AssumeRole"
        Condition = {
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
        }
      }
    ]
  })

  tags = merge(
    local.security_tags,
    {
      Name = "${local.name_prefix}-security-audit-role"
    }
  )
}

# Attach AWS managed SecurityAudit policy
resource "aws_iam_role_policy_attachment" "security_audit" {
  role       = aws_iam_role.security_audit.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/SecurityAudit"
}

# Attach ReadOnlyAccess for comprehensive visibility
resource "aws_iam_role_policy_attachment" "security_audit_readonly" {
  role       = aws_iam_role.security_audit.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/ReadOnlyAccess"
}

# ============================================================================
# CloudTrail Service Role
# ============================================================================

resource "aws_iam_role" "cloudtrail" {
  name        = "${local.name_prefix}-cloudtrail-role"
  description = "Service role for CloudTrail to write to CloudWatch Logs"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = local.security_tags
}

resource "aws_iam_role_policy" "cloudtrail_cloudwatch" {
  name = "${local.name_prefix}-cloudtrail-cloudwatch-policy"
  role = aws_iam_role.cloudtrail.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailCreateLogStream"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream"
        ]
        Resource = "arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group:/aws/cloudtrail/*:log-stream:*"
      },
      {
        Sid    = "AWSCloudTrailPutLogEvents"
        Effect = "Allow"
        Action = [
          "logs:PutLogEvents"
        ]
        Resource = "arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group:/aws/cloudtrail/*:log-stream:*"
      }
    ]
  })
}

# ============================================================================
# Config Service Role
# ============================================================================

resource "aws_iam_role" "config" {
  name        = "${local.name_prefix}-config-role"
  description = "Service role for AWS Config"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = local.security_tags
}

# Attach AWS managed Config policy
resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/ConfigRole"
}

# Additional permissions for Config to write to S3
resource "aws_iam_role_policy" "config_s3" {
  name = "${local.name_prefix}-config-s3-policy"
  role = aws_iam_role.config.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetBucketVersioning",
          "s3:PutObject",
          "s3:GetObject"
        ]
        Resource = [
          "arn:${local.partition}:s3:::${local.config_bucket_name}",
          "arn:${local.partition}:s3:::${local.config_bucket_name}/*"
        ]
      }
    ]
  })
}

# ============================================================================
# Lambda Execution Role (for automated remediation)
# ============================================================================

resource "aws_iam_role" "remediation_lambda" {
  name        = "${local.name_prefix}-remediation-lambda-role"
  description = "Role for Lambda functions performing automated remediation"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = local.security_tags
}

# Attach basic Lambda execution policy
resource "aws_iam_role_policy_attachment" "remediation_lambda_basic" {
  role       = aws_iam_role.remediation_lambda.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Custom policy for remediation actions
resource "aws_iam_role_policy" "remediation_lambda_actions" {
  name = "${local.name_prefix}-remediation-actions-policy"
  role = aws_iam_role.remediation_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "RemediationActions"
        Effect = "Allow"
        Action = [
          "ec2:StopInstances",
          "ec2:TerminateInstances",
          "ec2:ModifyInstanceAttribute",
          "s3:PutBucketPublicAccessBlock",
          "s3:PutBucketVersioning",
          "s3:PutBucketLogging",
          "iam:DeleteAccessKey",
          "iam:UpdateAccessKey",
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "*"
      }
    ]
  })
}

# ============================================================================
# Security Hub Service Role
# ============================================================================

resource "aws_iam_role" "security_hub" {
  name        = "${local.name_prefix}-security-hub-role"
  description = "Service role for Security Hub"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "securityhub.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = local.security_tags
}

# resource "aws_iam_role_policy_attachment" "security_hub" {
#   role       = aws_iam_role.security_hub.name
#   policy_arn = "arn:${local.partition}:iam::aws:policy/aws-service-role/SecurityHubServiceRolePolicy"
# }

# ============================================================================
# Support Role for Enterprise Support (CIS 1.20)
# ============================================================================

resource "aws_iam_role" "support" {
  count       = var.enable_support_role ? 1 : 0
  name        = "${local.name_prefix}-support-role"
  description = "Role for AWS Support access"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:${local.partition}:iam::${local.account_id}:root"
        }
        Action = "sts:AssumeRole"
        Condition = {
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
        }
      }
    ]
  })

  tags = local.security_tags
}

resource "aws_iam_role_policy_attachment" "support" {
  count      = var.enable_support_role ? 1 : 0
  role       = aws_iam_role.support[0].name
  policy_arn = "arn:${local.partition}:iam::aws:policy/AWSSupportAccess"
}

# ============================================================================
# Custom Policy: Deny Actions Without MFA (CIS 1.2)
# ============================================================================

resource "aws_iam_policy" "deny_without_mfa" {
  name        = "${local.name_prefix}-deny-without-mfa"
  description = "Deny sensitive actions if MFA is not present"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyAllExceptListedIfNoMFA"
        Effect = "Deny"
        NotAction = [
          "iam:CreateVirtualMFADevice",
          "iam:EnableMFADevice",
          "iam:GetUser",
          "iam:ListMFADevices",
          "iam:ListVirtualMFADevices",
          "iam:ResyncMFADevice",
          "sts:GetSessionToken",
          "iam:ChangePassword"
        ]
        Resource = "*"
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      }
    ]
  })

  tags = local.security_tags
}

# ============================================================================
# Custom Policy: Restrict Root Account Actions
# ============================================================================

resource "aws_iam_policy" "restrict_root" {
  name        = "${local.name_prefix}-restrict-root-account"
  description = "Deny specific actions for root account"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyRootAccountAccess"
        Effect = "Deny"
        Action = [
          "iam:CreateAccessKey",
          "iam:CreateUser",
          "iam:DeleteUser"
        ]
        Resource = "arn:${local.partition}:iam::${local.account_id}:root"
      }
    ]
  })

  tags = local.security_tags
}

# ============================================================================
# Outputs
# ============================================================================

output "security_audit_role_arn" {
  description = "ARN of the security audit role"
  value       = aws_iam_role.security_audit.arn
}

output "cloudtrail_role_arn" {
  description = "ARN of the CloudTrail service role"
  value       = aws_iam_role.cloudtrail.arn
}

output "config_role_arn" {
  description = "ARN of the Config service role"
  value       = aws_iam_role.config.arn
}

output "remediation_lambda_role_arn" {
  description = "ARN of the Lambda remediation role"
  value       = aws_iam_role.remediation_lambda.arn
}

output "password_policy_configured" {
  description = "Indicates if IAM password policy is configured"
  value       = true
}