# ============================================================================
# Terraform Outputs - AWS Security & Compliance Framework
# ============================================================================

# ============================================================================
# General Information
# ============================================================================

output "deployment_summary" {
  description = "Summary of deployed security framework"
  value = {
    project     = var.project_name
    environment = var.environment
    region      = local.region
    account_id  = local.account_id
  }
}

# ============================================================================
# IAM Configuration
# ============================================================================

output "iam_password_policy" {
  description = "IAM password policy status"
  value       = "configured"
}

# ============================================================================
# Threat Detection
# ============================================================================

output "guardduty_detector_id" {
  description = "GuardDuty detector ID"
  value       = var.enable_guardduty ? aws_guardduty_detector.main[0].id : "disabled"
}

output "guardduty_findings_bucket" {
  description = "S3 bucket for GuardDuty findings"
  value       = var.enable_guardduty ? aws_s3_bucket.guardduty_findings[0].id : "not_created"
}

# ============================================================================
# Security Hub
# ============================================================================

output "security_hub_arn" {
  description = "Security Hub ARN"
  value       = var.enable_security_hub ? aws_securityhub_account.main[0].arn : "disabled"
}

output "enabled_compliance_standards" {
  description = "List of enabled compliance standards"
  value = var.enable_security_hub ? {
    cis_1_2_0        = var.enable_cis_level_1
    cis_1_4_0        = var.enable_cis_level_2
    aws_foundational = true
    pci_dss          = var.enable_pci_dss
  } : {}
}

# ============================================================================
# AWS Config
# ============================================================================

output "config_recorder_id" {
  description = "Config recorder ID"
  value       = var.enable_config_rules ? aws_config_configuration_recorder.main[0].id : "disabled"
}

output "config_rules_deployed" {
  description = "Number of Config rules deployed"
  value = var.enable_config_rules ? (
    var.enable_cis_level_1 ? 20 : 0
  ) + (var.enable_cis_level_2 ? 1 : 0) + 3 : 0
}

# ============================================================================
# CloudTrail
# ============================================================================

output "cloudtrail_name" {
  description = "CloudTrail trail name"
  value       = var.enable_cloudtrail ? aws_cloudtrail.main[0].name : "disabled"
}

output "cloudtrail_log_group" {
  description = "CloudWatch log group for CloudTrail"
  value       = var.enable_cloudtrail ? aws_cloudwatch_log_group.cloudtrail[0].name : "not_created"
}

output "cloudtrail_bucket" {
  description = "S3 bucket for CloudTrail logs"
  value       = var.enable_cloudtrail ? aws_s3_bucket.cloudtrail[0].id : "not_created"
}

# ============================================================================
# KMS Keys
# ============================================================================

output "kms_keys" {
  description = "KMS key information"
  value = {
    cloudtrail_key_id = var.enable_cloudtrail ? aws_kms_key.cloudtrail[0].id : "not_created"
    s3_key_id         = var.enable_guardduty || var.enable_config_rules ? aws_kms_key.s3[0].id : "not_created"
    secrets_key_id    = aws_kms_key.secrets.id
    ebs_key_id        = var.enable_ebs_encryption ? aws_kms_key.ebs[0].id : "not_created"
  }
  sensitive = true
}

# ============================================================================
# S3 Buckets
# ============================================================================

output "s3_buckets" {
  description = "S3 buckets for security logs"
  value = {
    cloudtrail_bucket    = var.enable_cloudtrail ? aws_s3_bucket.cloudtrail[0].id : "not_created"
    config_bucket        = var.enable_config_rules ? aws_s3_bucket.config[0].id : "not_created"
    guardduty_bucket     = var.enable_guardduty ? aws_s3_bucket.guardduty_findings[0].id : "not_created"
    security_logs_bucket = var.enable_cloudtrail || var.enable_config_rules ? aws_s3_bucket.security_logs[0].id : "not_created"
  }
}

# ============================================================================
# SNS Topics
# ============================================================================

output "sns_topics" {
  description = "SNS topics for alerts"
  value = {
    security_alerts_topic   = aws_sns_topic.security_alerts.arn
    compliance_alerts_topic = aws_sns_topic.compliance_alerts.arn
  }
}

# ============================================================================
# IAM Roles
# ============================================================================

output "iam_roles" {
  description = "IAM roles created"
  value = {
    security_audit_role  = aws_iam_role.security_audit.arn
    cloudtrail_role      = aws_iam_role.cloudtrail.arn
    config_role          = aws_iam_role.config.arn
    remediation_role     = aws_iam_role.remediation_lambda.arn
    security_hub_role    = aws_iam_role.security_hub.arn
  }
}

# ============================================================================
# Compliance Score
# ============================================================================

output "compliance_dashboard_url" {
  description = "URL to view compliance dashboard"
  value       = "https://${local.region}.console.aws.amazon.com/securityhub/home?region=${local.region}#/standards"
}

output "config_dashboard_url" {
  description = "URL to view AWS Config dashboard"
  value       = "https://${local.region}.console.aws.amazon.com/config/home?region=${local.region}#/dashboard"
}

output "guardduty_dashboard_url" {
  description = "URL to view GuardDuty findings"
  value       = "https://${local.region}.console.aws.amazon.com/guardduty/home?region=${local.region}#/findings"
}

# ============================================================================
# Cost Estimation
# ============================================================================

output "estimated_monthly_cost" {
  description = "Estimated monthly cost breakdown"
  value = {
    guardduty     = var.enable_guardduty ? "$5" : "$0"
    security_hub  = var.enable_security_hub ? "$2" : "$0"
    config_rules  = var.enable_config_rules ? "$4" : "$0"
    cloudtrail    = var.enable_cloudtrail ? "$2" : "$0"
    kms           = "$1-2"
    s3_storage    = "$1"
    cloudwatch    = "$0.50"
    inspector     = var.enable_inspector ? "$0.50" : "$0"
    total         = "~$15-16/month"
  }
}

# ============================================================================
# Quick Access Commands
# ============================================================================

output "useful_commands" {
  description = "Useful commands for security operations"
  value = <<-EOT
    
    ═══════════════════════════════════════════════════════════════
    🔒 AWS Security Framework - Deployed Successfully!
    ═══════════════════════════════════════════════════════════════
    
    📊 View Security Hub Findings:
       aws securityhub get-findings \
         --filters '{"SeverityLabel":[{"Value":"CRITICAL","Comparison":"EQUALS"}]}' \
         --region ${local.region}
    
    🔍 View GuardDuty Findings:
       aws guardduty list-findings \
         --detector-id ${var.enable_guardduty ? aws_guardduty_detector.main[0].id : "DETECTOR_ID"} \
         --finding-criteria '{"Criterion":{"severity":{"Gte":7}}}' \
         --region ${local.region}
    
    📋 Check Config Compliance:
       aws configservice describe-compliance-by-config-rule \
         --region ${local.region}
    
    📝 View CloudTrail Events:
       aws cloudtrail lookup-events \
         --lookup-attributes AttributeKey=Username,AttributeValue=root \
         --region ${local.region}
    
    🔐 Get IAM Credential Report:
       aws iam generate-credential-report
       aws iam get-credential-report
    
    📊 View Security Dashboard:
       ${local.region}.console.aws.amazon.com/securityhub/home
    
    ═══════════════════════════════════════════════════════════════
    
  EOT
}

# ============================================================================
# Next Steps
# ============================================================================

output "next_steps" {
  description = "Recommended next steps after deployment"
  value = <<-EOT
    
    ✅ Next Steps:
    ═══════════════════════════════════════════════════════════════
    
    1. 📧 Verify Email Subscriptions:
       • Check ${var.alert_email} for SNS confirmation emails
       • Confirm both security and compliance alert subscriptions
    
    2. 📊 Review Security Hub Findings:
       • Visit: ${local.region}.console.aws.amazon.com/securityhub/home
       • Review initial compliance score
       • Address any critical/high findings
    
    3. 🔍 Check GuardDuty:
       • Wait 24-48 hours for baseline establishment
       • Review any initial findings
       • Configure suppression rules if needed
    
    4. 📋 Validate Config Rules:
       • Review compliance status of all rules
       • Remediate any non-compliant resources
       • Enable automated remediation where appropriate
    
    5. 🔐 Enforce MFA:
       • Enable MFA for all IAM users
       • Enforce MFA for root account
       • Test deny-without-MFA policy
    
    6. 📝 Document Procedures:
       • Create incident response runbook
       • Document escalation procedures
       • Train team on security tools
    
  EOT
}