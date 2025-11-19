# ============================================================================
# S3 Buckets for Security Logs Storage
# ============================================================================
# This file contains ONLY S3 bucket definitions
# CloudTrail resources are in cloudtrail.tf
# GuardDuty resources are in guardduty.tf
# ============================================================================

# ============================================================================
# CloudTrail S3 Bucket
# ============================================================================

resource "aws_s3_bucket" "cloudtrail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = local.cloudtrail_bucket_name

  tags = merge(
    local.security_tags,
    {
      Name = "${local.name_prefix}-cloudtrail-logs"
    }
  )
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.cloudtrail[0].arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id

  rule {
    id     = "archive-old-logs"
    status = "Enabled"
    filter {}
    transition {
      days          = var.s3_log_lifecycle_glacier
      storage_class = "GLACIER"
    }

    expiration {
      days = 2555  # 7 years retention for compliance
    }
  }
}

resource "aws_s3_bucket_logging" "cloudtrail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id

  target_bucket = aws_s3_bucket.security_logs[0].id
  target_prefix = "cloudtrail-bucket-logs/"
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail[0].arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail[0].arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      {
        Sid    = "DenyUnencryptedObjectUploads"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail[0].arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      },
      {
        Sid    = "DenyInsecureTransport"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:*"
        Resource = [
          aws_s3_bucket.cloudtrail[0].arn,
          "${aws_s3_bucket.cloudtrail[0].arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

# ============================================================================
# AWS Config S3 Bucket
# ============================================================================

resource "aws_s3_bucket" "config" {
  count  = var.enable_config_rules ? 1 : 0
  bucket = local.config_bucket_name

  tags = merge(
    local.security_tags,
    {
      Name = "${local.name_prefix}-config-logs"
    }
  )
}

resource "aws_s3_bucket_versioning" "config" {
  count  = var.enable_config_rules ? 1 : 0
  bucket = aws_s3_bucket.config[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config" {
  count  = var.enable_config_rules ? 1 : 0
  bucket = aws_s3_bucket.config[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3[0].arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "config" {
  count  = var.enable_config_rules ? 1 : 0
  bucket = aws_s3_bucket.config[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "config" {
  count  = var.enable_config_rules ? 1 : 0
  bucket = aws_s3_bucket.config[0].id

  rule {
    id     = "archive-old-configs"
    status = "Enabled"
    filter {}
    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 2555  # 7 years retention
    }
  }
}

resource "aws_s3_bucket_policy" "config" {
  count  = var.enable_config_rules ? 1 : 0
  bucket = aws_s3_bucket.config[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSConfigBucketPermissionsCheck"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.config[0].arn
      },
      {
        Sid    = "AWSConfigBucketExistenceCheck"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:ListBucket"
        Resource = aws_s3_bucket.config[0].arn
      },
      {
        Sid    = "AWSConfigWrite"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.config[0].arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      {
        Sid    = "DenyInsecureTransport"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:*"
        Resource = [
          aws_s3_bucket.config[0].arn,
          "${aws_s3_bucket.config[0].arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

# ============================================================================
# Security Logs Aggregation Bucket
# ============================================================================

resource "aws_s3_bucket" "security_logs" {
  count  = var.enable_cloudtrail || var.enable_config_rules ? 1 : 0
  bucket = local.security_logs_bucket_name

  tags = merge(
    local.security_tags,
    {
      Name = "${local.name_prefix}-security-logs-aggregation"
    }
  )
}

resource "aws_s3_bucket_versioning" "security_logs" {
  count  = var.enable_cloudtrail || var.enable_config_rules ? 1 : 0
  bucket = aws_s3_bucket.security_logs[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "security_logs" {
  count  = var.enable_cloudtrail || var.enable_config_rules ? 1 : 0
  bucket = aws_s3_bucket.security_logs[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "security_logs" {
  count  = var.enable_cloudtrail || var.enable_config_rules ? 1 : 0
  bucket = aws_s3_bucket.security_logs[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "security_logs" {
  count  = var.enable_cloudtrail || var.enable_config_rules ? 1 : 0
  bucket = aws_s3_bucket.security_logs[0].id

  rule {
    id     = "archive-aggregated-logs"
    status = "Enabled"
    filter {}
    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }
  }
}

resource "aws_s3_bucket_policy" "security_logs" {
  count  = var.enable_cloudtrail || var.enable_config_rules ? 1 : 0
  bucket = aws_s3_bucket.security_logs[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowS3LogDelivery"
        Effect = "Allow"
        Principal = {
          Service = "logging.s3.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.security_logs[0].arn}/*"
      },
      {
        Sid    = "DenyInsecureTransport"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:*"
        Resource = [
          aws_s3_bucket.security_logs[0].arn,
          "${aws_s3_bucket.security_logs[0].arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

# ============================================================================
# Outputs
# ============================================================================

output "cloudtrail_bucket_name" {
  description = "S3 bucket name for CloudTrail logs"
  value       = var.enable_cloudtrail ? aws_s3_bucket.cloudtrail[0].id : null
}

output "cloudtrail_bucket_arn" {
  description = "S3 bucket ARN for CloudTrail logs"
  value       = var.enable_cloudtrail ? aws_s3_bucket.cloudtrail[0].arn : null
}

output "config_bucket_name" {
  description = "S3 bucket name for Config logs"
  value       = var.enable_config_rules ? aws_s3_bucket.config[0].id : null
}

output "config_bucket_arn" {
  description = "S3 bucket ARN for Config logs"
  value       = var.enable_config_rules ? aws_s3_bucket.config[0].arn : null
}

output "security_logs_bucket_name" {
  description = "S3 bucket name for aggregated security logs"
  value       = var.enable_cloudtrail || var.enable_config_rules ? aws_s3_bucket.security_logs[0].id : null
}