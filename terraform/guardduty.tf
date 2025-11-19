# ============================================================================
# AWS GuardDuty - Intelligent Threat Detection
# ============================================================================

# ============================================================================
# Enable GuardDuty
# ============================================================================

resource "aws_guardduty_detector" "main" {
  count = var.enable_guardduty ? 1 : 0

  enable                       = true
  finding_publishing_frequency = var.guardduty_finding_frequency

  # Enable S3 Protection
  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }

  tags = merge(
    local.security_tags,
    {
      Name = "${local.name_prefix}-guardduty-detector"
    }
  )
}

# ============================================================================
# GuardDuty S3 Bucket for Findings Export
# ============================================================================

resource "aws_s3_bucket" "guardduty_findings" {
  count  = var.enable_guardduty ? 1 : 0
  bucket = "${local.name_prefix}-guardduty-findings-${local.account_id}"

  tags = merge(
    local.security_tags,
    {
      Name = "${local.name_prefix}-guardduty-findings"
    }
  )
}

resource "aws_s3_bucket_versioning" "guardduty_findings" {
  count  = var.enable_guardduty ? 1 : 0
  bucket = aws_s3_bucket.guardduty_findings[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "guardduty_findings" {
  count  = var.enable_guardduty ? 1 : 0
  bucket = aws_s3_bucket.guardduty_findings[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3[0].arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "guardduty_findings" {
  count  = var.enable_guardduty ? 1 : 0
  bucket = aws_s3_bucket.guardduty_findings[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "guardduty_findings" {
  count  = var.enable_guardduty ? 1 : 0
  bucket = aws_s3_bucket.guardduty_findings[0].id

  rule {
    id     = "archive-old-findings"
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

# Bucket policy for GuardDuty
resource "aws_s3_bucket_policy" "guardduty_findings" {
  count  = var.enable_guardduty ? 1 : 0
  bucket = aws_s3_bucket.guardduty_findings[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowGuardDutyToWrite"
        Effect = "Allow"
        Principal = {
          Service = "guardduty.amazonaws.com"
        }
        Action = [
          "s3:PutObject",
          "s3:GetBucketLocation"
        ]
        Resource = [
          aws_s3_bucket.guardduty_findings[0].arn,
          "${aws_s3_bucket.guardduty_findings[0].arn}/*"
        ]
      },
      {
        Sid    = "DenyUnencryptedObjectUploads"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:PutObject"
        Resource = "${aws_s3_bucket.guardduty_findings[0].arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      }
    ]
  })
}

# ============================================================================
# GuardDuty Publishing Destination
# ============================================================================

resource "aws_guardduty_publishing_destination" "main" {
  count = var.enable_guardduty ? 1 : 0

  detector_id     = aws_guardduty_detector.main[0].id
  destination_arn = aws_s3_bucket.guardduty_findings[0].arn
  kms_key_arn     = aws_kms_key.s3[0].arn

  destination_type = "S3"

  depends_on = [
    aws_s3_bucket_policy.guardduty_findings
  ]
}

# ============================================================================
# CloudWatch Event Rule for Critical GuardDuty Findings
# ============================================================================

resource "aws_cloudwatch_event_rule" "guardduty_critical" {
  count = var.enable_guardduty ? 1 : 0

  name        = "${local.name_prefix}-guardduty-critical-findings"
  description = "Capture critical GuardDuty findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [
        { numeric = [">", 7] }
      ]
    }
  })

  tags = local.security_tags
}

resource "aws_cloudwatch_event_target" "guardduty_critical_sns" {
  count = var.enable_guardduty ? 1 : 0

  rule      = aws_cloudwatch_event_rule.guardduty_critical[0].name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.security_alerts.arn

  input_transformer {
    input_paths = {
      severity    = "$.detail.severity"
      finding     = "$.detail.type"
      region      = "$.detail.region"
      account     = "$.detail.accountId"
      time        = "$.detail.updatedAt"
      description = "$.detail.description"
      resource    = "$.detail.resource.resourceType"
    }

    input_template = <<EOF
"🚨 CRITICAL GuardDuty Finding Alert"
""
"Severity: <severity>"
"Finding Type: <finding>"
"Description: <description>"
""
"Resource Type: <resource>"
"Account: <account>"
"Region: <region>"
"Time: <time>"
""
"Action Required: Investigate immediately"
EOF
  }
}

# ============================================================================
# CloudWatch Event Rule for High Severity Findings
# ============================================================================

resource "aws_cloudwatch_event_rule" "guardduty_high" {
  count = var.enable_guardduty ? 1 : 0

  name        = "${local.name_prefix}-guardduty-high-findings"
  description = "Capture high severity GuardDuty findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [
        { numeric = [">=", 4, "<=", 6.9] }
      ]
    }
  })

  tags = local.security_tags
}

resource "aws_cloudwatch_event_target" "guardduty_high_sns" {
  count = var.enable_guardduty ? 1 : 0

  rule      = aws_cloudwatch_event_rule.guardduty_high[0].name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.security_alerts.arn

  input_transformer {
    input_paths = {
      severity    = "$.detail.severity"
      finding     = "$.detail.type"
      description = "$.detail.description"
      account     = "$.detail.accountId"
    }

    input_template = <<EOF
"⚠️ High Severity GuardDuty Finding"
""
"Severity: <severity>"
"Type: <finding>"
"Description: <description>"
"Account: <account>"
EOF
  }
}

# ============================================================================
# GuardDuty Filter for Suppressing Low-Priority Findings
# ============================================================================

resource "aws_guardduty_filter" "suppress_low_findings" {
  count = var.enable_guardduty ? 1 : 0

  detector_id = aws_guardduty_detector.main[0].id
  name        = "suppress-low-priority-findings"
  action      = "ARCHIVE"
  rank        = 1

  finding_criteria {
    criterion {
      field  = "severity"
      less_than = "4"
    }

    criterion {
      field = "type"
      not_equals = [
        "Recon:EC2/PortProbeUnprotectedPort",
        "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration"
      ]
    }
  }
}

# ============================================================================
# GuardDuty IPSet for Trusted IPs (Optional)
# ============================================================================

# Example: Create an IPSet for trusted IP addresses
# Uncomment and configure if needed

# resource "aws_guardduty_ipset" "trusted_ips" {
#   count = var.enable_guardduty ? 1 : 0
#
#   detector_id = aws_guardduty_detector.main[0].id
#   name        = "trusted-ip-addresses"
#   format      = "TXT"
#   location    = "s3://${aws_s3_bucket.guardduty_findings[0].id}/trusted-ips.txt"
#   activate    = true
# }

# ============================================================================
# GuardDuty ThreatIntelSet for Known Malicious IPs (Optional)
# ============================================================================

# Example: Create a ThreatIntelSet
# Uncomment and configure if needed

# resource "aws_guardduty_threatintelset" "malicious_ips" {
#   count = var.enable_guardduty ? 1 : 0
#
#   detector_id = aws_guardduty_detector.main[0].id
#   name        = "known-malicious-ips"
#   format      = "TXT"
#   location    = "s3://${aws_s3_bucket.guardduty_findings[0].id}/malicious-ips.txt"
#   activate    = true
# }
