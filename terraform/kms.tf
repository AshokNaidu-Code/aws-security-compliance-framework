# ============================================================================
# AWS KMS - Customer Managed Keys for Encryption
# ============================================================================

# ============================================================================
# KMS Key for CloudTrail Logs
# ============================================================================

resource "aws_kms_key" "cloudtrail" {
  count = var.enable_cloudtrail ? 1 : 0

  description             = "KMS key for CloudTrail log encryption"
  deletion_window_in_days = var.kms_deletion_window
  enable_key_rotation     = var.enable_kms_key_rotation

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:${local.partition}:iam::${local.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow CloudTrail to encrypt logs"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringLike = {
            "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:${local.partition}:cloudtrail:*:${local.account_id}:trail/*"
          }
        }
      },
      {
        Sid    = "Allow CloudTrail to describe key"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "kms:DescribeKey"
        Resource = "*"
      },
      {
        Sid    = "Allow CloudWatch Logs"
        Effect = "Allow"
        Principal = {
          Service = "logs.${local.region}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:CreateGrant",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group:*"
          }
        }
      }
    ]
  })

  tags = merge(
    local.security_tags,
    {
      Name = "${local.name_prefix}-cloudtrail-key"
    }
  )
}

resource "aws_kms_alias" "cloudtrail" {
  count = var.enable_cloudtrail ? 1 : 0

  name          = local.cloudtrail_kms_alias
  target_key_id = aws_kms_key.cloudtrail[0].key_id
}

# ============================================================================
# KMS Key for S3 Encryption
# ============================================================================

resource "aws_kms_key" "s3" {
  count = var.enable_guardduty || var.enable_config_rules ? 1 : 0

  description             = "KMS key for S3 bucket encryption"
  deletion_window_in_days = var.kms_deletion_window
  enable_key_rotation     = var.enable_kms_key_rotation

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:${local.partition}:iam::${local.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow S3 to use the key"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "Allow Config to use the key"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "Allow GuardDuty to use the key"
        Effect = "Allow"
        Principal = {
          Service = "guardduty.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = merge(
    local.security_tags,
    {
      Name = "${local.name_prefix}-s3-key"
    }
  )
}

resource "aws_kms_alias" "s3" {
  count = var.enable_guardduty || var.enable_config_rules ? 1 : 0

  name          = local.s3_kms_alias
  target_key_id = aws_kms_key.s3[0].key_id
}

# ============================================================================
# KMS Key for Secrets Manager
# ============================================================================

resource "aws_kms_key" "secrets" {
  description             = "KMS key for Secrets Manager encryption"
  deletion_window_in_days = var.kms_deletion_window
  enable_key_rotation     = var.enable_kms_key_rotation

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:${local.partition}:iam::${local.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow Secrets Manager to use the key"
        Effect = "Allow"
        Principal = {
          Service = "secretsmanager.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:CreateGrant"
        ]
        Resource = "*"
      }
    ]
  })

  tags = merge(
    local.security_tags,
    {
      Name = "${local.name_prefix}-secrets-key"
    }
  )
}

resource "aws_kms_alias" "secrets" {
  name          = local.secrets_kms_alias
  target_key_id = aws_kms_key.secrets.key_id
}

# ============================================================================
# KMS Key for EBS Volume Encryption (Optional)
# ============================================================================

resource "aws_kms_key" "ebs" {
  count = var.enable_ebs_encryption ? 1 : 0

  description             = "KMS key for EBS volume encryption"
  deletion_window_in_days = var.kms_deletion_window
  enable_key_rotation     = var.enable_kms_key_rotation

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:${local.partition}:iam::${local.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow EC2 to use the key"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:CreateGrant"
        ]
        Resource = "*"
      }
    ]
  })

  tags = merge(
    local.security_tags,
    {
      Name = "${local.name_prefix}-ebs-key"
    }
  )
}

resource "aws_kms_alias" "ebs" {
  count = var.enable_ebs_encryption ? 1 : 0

  name          = "alias/${local.name_prefix}-ebs"
  target_key_id = aws_kms_key.ebs[0].key_id
}

# Enable EBS encryption by default
resource "aws_ebs_encryption_by_default" "enabled" {
  count = var.enable_ebs_encryption ? 1 : 0

  enabled = true
}

resource "aws_ebs_default_kms_key" "default" {
  count = var.enable_ebs_encryption ? 1 : 0

  key_arn = aws_kms_key.ebs[0].arn
}

# ============================================================================
# Outputs
# ============================================================================

output "cloudtrail_kms_key_id" {
  description = "KMS key ID for CloudTrail"
  value       = var.enable_cloudtrail ? aws_kms_key.cloudtrail[0].id : null
}

output "cloudtrail_kms_key_arn" {
  description = "KMS key ARN for CloudTrail"
  value       = var.enable_cloudtrail ? aws_kms_key.cloudtrail[0].arn : null
}

output "s3_kms_key_id" {
  description = "KMS key ID for S3"
  value       = var.enable_guardduty || var.enable_config_rules ? aws_kms_key.s3[0].id : null
}

output "s3_kms_key_arn" {
  description = "KMS key ARN for S3"
  value       = var.enable_guardduty || var.enable_config_rules ? aws_kms_key.s3[0].arn : null
}

output "secrets_kms_key_id" {
  description = "KMS key ID for Secrets Manager"
  value       = aws_kms_key.secrets.id
}

output "secrets_kms_key_arn" {
  description = "KMS key ARN for Secrets Manager"
  value       = aws_kms_key.secrets.arn
}

output "ebs_encryption_enabled" {
  description = "EBS encryption by default status"
  value       = var.enable_ebs_encryption
}