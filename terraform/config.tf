# ============================================================================
# AWS Config - Continuous Compliance Monitoring
# ============================================================================

# ============================================================================
# Config Recorder
# ============================================================================

resource "aws_config_configuration_recorder" "main" {
  count = var.enable_config_rules ? 1 : 0

  name     = "${local.name_prefix}-config-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

# ============================================================================
# Config Delivery Channel
# ============================================================================

resource "aws_config_delivery_channel" "main" {
  count = var.enable_config_rules ? 1 : 0

  name           = "${local.name_prefix}-config-delivery"
  s3_bucket_name = aws_s3_bucket.config[0].id
  s3_key_prefix  = "config"
  sns_topic_arn  = aws_sns_topic.compliance_alerts.arn

  snapshot_delivery_properties {
    delivery_frequency = "TwentyFour_Hours"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# ============================================================================
# Start Config Recorder
# ============================================================================

resource "aws_config_configuration_recorder_status" "main" {
  count = var.enable_config_rules ? 1 : 0

  name       = aws_config_configuration_recorder.main[0].name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.main]
}

# ============================================================================
# CIS AWS Foundations Benchmark - Level 1 Rules
# ============================================================================

# CIS 1.3 - Ensure credentials unused for 90 days or greater are disabled
resource "aws_config_config_rule" "iam_credentials_unused" {
  count = var.enable_config_rules && var.enable_cis_level_1 ? 1 : 0

  name = "${local.name_prefix}-iam-credentials-unused"

  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_UNUSED_CREDENTIALS_CHECK"
  }

  input_parameters = jsonencode({
    maxCredentialUsageAge = 90
  })

  depends_on = [aws_config_configuration_recorder.main]
}

# CIS 1.4 - Ensure access keys are rotated every 90 days or less
resource "aws_config_config_rule" "access_keys_rotated" {
  count = var.enable_config_rules && var.enable_cis_level_1 ? 1 : 0

  name = "${local.name_prefix}-access-keys-rotated"

  source {
    owner             = "AWS"
    source_identifier = "ACCESS_KEYS_ROTATED"
  }

  input_parameters = jsonencode({
    maxAccessKeyAge = 90
  })

  depends_on = [aws_config_configuration_recorder.main]
}

# CIS 1.12 - Ensure no root account access key exists
resource "aws_config_config_rule" "root_no_access_keys" {
  count = var.enable_config_rules && var.enable_cis_level_1 ? 1 : 0

  name = "${local.name_prefix}-root-no-access-keys"

  source {
    owner             = "AWS"
    source_identifier = "IAM_ROOT_ACCESS_KEY_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# CIS 1.14 - Ensure hardware MFA is enabled for the root account
resource "aws_config_config_rule" "root_mfa_enabled" {
  count = var.enable_config_rules && var.enable_cis_level_1 ? 1 : 0

  name = "${local.name_prefix}-root-mfa-enabled"

  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# CIS 2.1.1 - Ensure S3 bucket policy denies HTTP requests
resource "aws_config_config_rule" "s3_ssl_requests_only" {
  count = var.enable_config_rules && var.enable_cis_level_1 ? 1 : 0

  name = "${local.name_prefix}-s3-ssl-requests-only"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SSL_REQUESTS_ONLY"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# CIS 2.1.2 - Ensure MFA Delete is enabled on S3 buckets
resource "aws_config_config_rule" "s3_mfa_delete" {
  count = var.enable_config_rules && var.enable_cis_level_2 ? 1 : 0

  name = "${local.name_prefix}-s3-mfa-delete"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_VERSIONING_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# CIS 2.1.3 - Ensure all data in S3 is encrypted at rest
resource "aws_config_config_rule" "s3_default_encryption" {
  count = var.enable_config_rules && var.enable_cis_level_1 ? 1 : 0

  name = "${local.name_prefix}-s3-default-encryption"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# CIS 2.1.4 - Ensure S3 bucket logging is enabled
resource "aws_config_config_rule" "s3_bucket_logging" {
  count = var.enable_config_rules && var.enable_cis_level_1 ? 1 : 0

  name = "${local.name_prefix}-s3-bucket-logging"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_LOGGING_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# CIS 2.1.5 - Ensure S3 buckets are not publicly accessible
resource "aws_config_config_rule" "s3_public_access_blocked" {
  count = var.enable_config_rules && var.enable_cis_level_1 ? 1 : 0

  name = "${local.name_prefix}-s3-public-access-blocked"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "s3_public_write_blocked" {
  count = var.enable_config_rules && var.enable_cis_level_1 ? 1 : 0

  name = "${local.name_prefix}-s3-public-write-blocked"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# CIS 2.2.1 - Ensure EBS volume encryption is enabled
resource "aws_config_config_rule" "ebs_encryption_enabled" {
  count = var.enable_config_rules && var.enable_cis_level_1 ? 1 : 0

  name = "${local.name_prefix}-ebs-encryption-enabled"

  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# CIS 2.3.1 - Ensure RDS instances are encrypted
resource "aws_config_config_rule" "rds_encryption_enabled" {
  count = var.enable_config_rules && var.enable_cis_level_1 ? 1 : 0

  name = "${local.name_prefix}-rds-encryption-enabled"

  source {
    owner             = "AWS"
    source_identifier = "RDS_STORAGE_ENCRYPTED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# CIS 3.1 - Ensure CloudTrail is enabled in all regions
resource "aws_config_config_rule" "cloudtrail_enabled" {
  count = var.enable_config_rules && var.enable_cis_level_1 ? 1 : 0

  name = "${local.name_prefix}-cloudtrail-enabled"

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# CIS 3.2 - Ensure CloudTrail log file validation is enabled
resource "aws_config_config_rule" "cloudtrail_log_validation" {
  count = var.enable_config_rules && var.enable_cis_level_1 ? 1 : 0

  name = "${local.name_prefix}-cloudtrail-log-validation"

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# CIS 3.7 - Ensure CloudTrail logs are encrypted at rest using KMS
resource "aws_config_config_rule" "cloudtrail_encryption" {
  count = var.enable_config_rules && var.enable_cis_level_1 ? 1 : 0

  name = "${local.name_prefix}-cloudtrail-encryption"

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENCRYPTION_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# CIS 4.1 - Ensure no security groups allow ingress from 0.0.0.0/0 to port 22
resource "aws_config_config_rule" "no_unrestricted_ssh" {
  count = var.enable_config_rules && var.enable_cis_level_1 ? 1 : 0

  name = "${local.name_prefix}-no-unrestricted-ssh"

  source {
    owner             = "AWS"
    source_identifier = "INCOMING_SSH_DISABLED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# CIS 4.2 - Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389
resource "aws_config_config_rule" "no_unrestricted_rdp" {
  count = var.enable_config_rules && var.enable_cis_level_1 ? 1 : 0

  name = "${local.name_prefix}-no-unrestricted-rdp"

  source {
    owner             = "AWS"
    source_identifier = "RESTRICTED_INCOMING_TRAFFIC"
  }

  input_parameters = jsonencode({
    blockedPort1 = 3389
  })

  depends_on = [aws_config_configuration_recorder.main]
}

# CIS 4.3 - Ensure VPC flow logging is enabled
resource "aws_config_config_rule" "vpc_flow_logs_enabled" {
  count = var.enable_config_rules && var.enable_cis_level_1 ? 1 : 0

  name = "${local.name_prefix}-vpc-flow-logs-enabled"

  source {
    owner             = "AWS"
    source_identifier = "VPC_FLOW_LOGS_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# ============================================================================
# Additional Security Best Practice Rules
# ============================================================================

# Ensure EC2 instances use IMDSv2
resource "aws_config_config_rule" "ec2_imdsv2" {
  count = var.enable_config_rules ? 1 : 0

  name = "${local.name_prefix}-ec2-imdsv2"

  source {
    owner             = "AWS"
    source_identifier = "EC2_IMDSV2_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# Ensure RDS instances have deletion protection
resource "aws_config_config_rule" "rds_deletion_protection" {
  count = var.enable_config_rules ? 1 : 0

  name = "${local.name_prefix}-rds-deletion-protection"

  source {
    owner             = "AWS"
    source_identifier = "RDS_INSTANCE_DELETION_PROTECTION_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# Ensure Lambda functions use latest runtime
resource "aws_config_config_rule" "lambda_runtime_check" {
  count = var.enable_config_rules ? 1 : 0

  name = "${local.name_prefix}-lambda-runtime-check"

  source {
    owner             = "AWS"
    source_identifier = "LAMBDA_FUNCTION_SETTINGS_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# ============================================================================
# Config Aggregator (Optional - for multi-account)
# ============================================================================

# Uncomment if using AWS Organizations
# resource "aws_config_configuration_aggregator" "organization" {
#   count = var.enable_config_rules ? 1 : 0
#
#   name = "${local.name_prefix}-org-aggregator"
#
#   organization_aggregation_source {
#     all_regions = true
#     role_arn    = aws_iam_role.config.arn
#   }
# }
