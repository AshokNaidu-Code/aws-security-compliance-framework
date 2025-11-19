# ============================================================================
# AWS Security Hub - Centralized Security & Compliance View
# ============================================================================

# ============================================================================
# Enable Security Hub
# ============================================================================

resource "aws_securityhub_account" "main" {
  count = var.enable_security_hub ? 1 : 0

  enable_default_standards = false

  depends_on = [
    aws_guardduty_detector.main
  ]
}

# ============================================================================
# Enable CIS AWS Foundations Benchmark v1.2.0
# ============================================================================

resource "aws_securityhub_standards_subscription" "cis_1_2_0" {
  count         = var.enable_security_hub && var.enable_cis_level_1 ? 1 : 0
  standards_arn = "arn:${local.partition}:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"

  depends_on = [aws_securityhub_account.main]
}

# ============================================================================
# Enable CIS AWS Foundations Benchmark v1.4.0 (Latest)
# ============================================================================

resource "aws_securityhub_standards_subscription" "cis_1_4_0" {
  count         = var.enable_security_hub && var.enable_cis_level_2 ? 1 : 0
  standards_arn = "arn:${local.partition}:securityhub:${local.region}::standards/cis-aws-foundations-benchmark/v/1.4.0"

  depends_on = [aws_securityhub_account.main]
}

# ============================================================================
# Enable AWS Foundational Security Best Practices
# ============================================================================

resource "aws_securityhub_standards_subscription" "aws_foundational" {
  count         = var.enable_security_hub ? 1 : 0
  standards_arn = "arn:${local.partition}:securityhub:${local.region}::standards/aws-foundational-security-best-practices/v/1.0.0"

  depends_on = [aws_securityhub_account.main]
}

# ============================================================================
# Enable PCI-DSS Standard
# ============================================================================

resource "aws_securityhub_standards_subscription" "pci_dss" {
  count         = var.enable_security_hub && var.enable_pci_dss ? 1 : 0
  standards_arn = "arn:${local.partition}:securityhub:${local.region}::standards/pci-dss/v/3.2.1"

  depends_on = [aws_securityhub_account.main]
}

# ============================================================================
# Product Integration: GuardDuty
# ============================================================================

resource "aws_securityhub_product_subscription" "guardduty" {
  count       = var.enable_security_hub && var.enable_guardduty ? 1 : 0
  product_arn = "arn:${local.partition}:securityhub:${local.region}::product/aws/guardduty"

  depends_on = [
    aws_securityhub_account.main,
    aws_guardduty_detector.main
  ]
}

# ============================================================================
# Product Integration: Inspector
# ============================================================================

resource "aws_securityhub_product_subscription" "inspector" {
  count       = var.enable_security_hub && var.enable_inspector ? 1 : 0
  product_arn = "arn:${local.partition}:securityhub:${local.region}::product/aws/inspector"

  depends_on = [aws_securityhub_account.main]
}

# ============================================================================
# Product Integration: IAM Access Analyzer
# ============================================================================

resource "aws_securityhub_product_subscription" "access_analyzer" {
  count       = var.enable_security_hub ? 1 : 0
  product_arn = "arn:${local.partition}:securityhub:${local.region}::product/aws/access-analyzer"

  depends_on = [aws_securityhub_account.main]
}

# ============================================================================
# CloudWatch Event Rule for Critical Security Hub Findings
# ============================================================================

resource "aws_cloudwatch_event_rule" "security_hub_critical" {
  count = var.enable_security_hub ? 1 : 0

  name        = "${local.name_prefix}-security-hub-critical"
  description = "Capture critical Security Hub findings"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity = {
          Label = ["CRITICAL"]
        }
        Workflow = {
          Status = ["NEW"]
        }
      }
    }
  })

  tags = local.security_tags
}

resource "aws_cloudwatch_event_target" "security_hub_critical_sns" {
  count = var.enable_security_hub ? 1 : 0

  rule      = aws_cloudwatch_event_rule.security_hub_critical[0].name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.security_alerts.arn

  input_transformer {
    input_paths = {
      title       = "$.detail.findings[0].Title"
      severity    = "$.detail.findings[0].Severity.Label"
      description = "$.detail.findings[0].Description"
      resource    = "$.detail.findings[0].Resources[0].Id"
      compliance  = "$.detail.findings[0].Compliance.Status"
      account     = "$.detail.findings[0].AwsAccountId"
      region      = "$.detail.findings[0].Resources[0].Region"
    }

    input_template = <<EOF
"🔴 CRITICAL Security Hub Finding"
""
"Title: <title>"
"Severity: <severity>"
"Compliance Status: <compliance>"
""
"Description: <description>"
""
"Affected Resource: <resource>"
"Account: <account>"
"Region: <region>"
""
"Action Required: Immediate investigation and remediation"
EOF
  }
}

# ============================================================================
# CloudWatch Event Rule for High Severity Findings
# ============================================================================

resource "aws_cloudwatch_event_rule" "security_hub_high" {
  count = var.enable_security_hub ? 1 : 0

  name        = "${local.name_prefix}-security-hub-high"
  description = "Capture high severity Security Hub findings"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity = {
          Label = ["HIGH"]
        }
        Workflow = {
          Status = ["NEW"]
        }
      }
    }
  })

  tags = local.security_tags
}

resource "aws_cloudwatch_event_target" "security_hub_high_sns" {
  count = var.enable_security_hub ? 1 : 0

  rule      = aws_cloudwatch_event_rule.security_hub_high[0].name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.security_alerts.arn

  input_transformer {
    input_paths = {
      title    = "$.detail.findings[0].Title"
      severity = "$.detail.findings[0].Severity.Label"
      resource = "$.detail.findings[0].Resources[0].Id"
    }

    input_template = <<EOF
"⚠️ High Severity Security Hub Finding"
""
"Title: <title>"
"Severity: <severity>"
"Resource: <resource>"
EOF
  }
}

# ============================================================================
# CloudWatch Event Rule for Compliance Changes
# ============================================================================

resource "aws_cloudwatch_event_rule" "compliance_change" {
  count = var.enable_security_hub ? 1 : 0

  name        = "${local.name_prefix}-compliance-status-change"
  description = "Capture compliance status changes"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Compliance = {
          Status = ["FAILED"]
        }
      }
    }
  })

  tags = local.security_tags
}

resource "aws_cloudwatch_event_target" "compliance_change_sns" {
  count = var.enable_security_hub ? 1 : 0

  rule      = aws_cloudwatch_event_rule.compliance_change[0].name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.compliance_alerts.arn

  input_transformer {
    input_paths = {
      title      = "$.detail.findings[0].Title"
      compliance = "$.detail.findings[0].Compliance.Status"
      standard   = "$.detail.findings[0].ProductFields.StandardsArn"
      resource   = "$.detail.findings[0].Resources[0].Id"
    }

    input_template = <<EOF
"📋 Compliance Status Change Alert"
""
"Control: <title>"
"Status: <compliance>"
"Standard: <standard>"
"Resource: <resource>"
""
"Action: Review and remediate compliance violation"
EOF
  }
}

# ============================================================================
# Insight: Critical and High Findings by Resource
# ============================================================================

resource "aws_securityhub_insight" "critical_high_by_resource" {
  count = var.enable_security_hub ? 1 : 0
  depends_on = [
    aws_securityhub_account.main,
    aws_securityhub_standards_subscription.aws_foundational
  ]
  filters {
    severity_label {
      comparison = "EQUALS"
      value      = "CRITICAL"
    }
    severity_label {
      comparison = "EQUALS"
      value      = "HIGH"
    }
  }

  group_by_attribute = "ResourceId"

  name = "${local.name_prefix}-critical-high-by-resource"
}
# ============================================================================
# Insight: Failed Compliance Checks
# ============================================================================

resource "aws_securityhub_insight" "failed_compliance" {
  count = var.enable_security_hub ? 1 : 0
  depends_on = [
    aws_securityhub_account.main,
    aws_securityhub_standards_subscription.aws_foundational
  ]
  filters {
    compliance_status {
      comparison = "EQUALS"
      value      = "FAILED"
    }
  }

  group_by_attribute = "ComplianceStatus"

  name = "${local.name_prefix}-failed-compliance-checks"
}

# ============================================================================
# Action Target for Remediation Workflow
# ============================================================================

resource "aws_securityhub_action_target" "remediation" {
  count = var.enable_security_hub ? 1 : 0

  name        = "trigger-remediation"
  identifier  = "TriggerRemediation"
  description = "Trigger automated remediation workflow"
}

