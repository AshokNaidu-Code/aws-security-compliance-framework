# ============================================================================
# Input Variables for AWS Security & Compliance Framework
# ============================================================================

# ============================================================================
# General Configuration
# ============================================================================

variable "project_name" {
  description = "Name of the project"
  type        = string
  default     = "security-framework"
}

variable "environment" {
  description = "Environment name (dev, staging, production)"
  type        = string
  default     = "production"

  validation {
    condition     = contains(["dev", "staging", "production"], var.environment)
    error_message = "Environment must be dev, staging, or production."
  }
}

variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

# ============================================================================
# Alerting Configuration
# ============================================================================

variable "alert_email" {
  description = "Email address for security and compliance alerts"
  type        = string
  default     = ""
}

variable "slack_webhook_url" {
  description = "Slack webhook URL for alerts (optional)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "enable_medium_alerts" {
  description = "Enable separate SNS topic for medium priority alerts"
  type        = bool
  default     = false
}

# ============================================================================
# IAM Password Policy Configuration (CIS 1.5-1.11)
# ============================================================================

variable "password_minimum_length" {
  description = "Minimum password length"
  type        = number
  default     = 14

  validation {
    condition     = var.password_minimum_length >= 14
    error_message = "Password minimum length must be at least 14 characters (CIS requirement)."
  }
}

variable "password_max_age" {
  description = "Maximum password age in days"
  type        = number
  default     = 90

  validation {
    condition     = var.password_max_age <= 90
    error_message = "Password max age must be 90 days or less (CIS requirement)."
  }
}

variable "password_reuse_prevention" {
  description = "Number of passwords to remember"
  type        = number
  default     = 24

  validation {
    condition     = var.password_reuse_prevention >= 24
    error_message = "Password reuse prevention must remember at least 24 passwords (CIS requirement)."
  }
}

variable "require_uppercase" {
  description = "Require at least one uppercase letter"
  type        = bool
  default     = true
}

variable "require_lowercase" {
  description = "Require at least one lowercase letter"
  type        = bool
  default     = true
}

variable "require_numbers" {
  description = "Require at least one number"
  type        = bool
  default     = true
}

variable "require_symbols" {
  description = "Require at least one non-alphanumeric character"
  type        = bool
  default     = true
}

# ============================================================================
# GuardDuty Configuration
# ============================================================================

variable "enable_guardduty" {
  description = "Enable AWS GuardDuty threat detection"
  type        = bool
  default     = true
}

variable "guardduty_finding_frequency" {
  description = "GuardDuty finding publishing frequency"
  type        = string
  default     = "FIFTEEN_MINUTES"

  validation {
    condition     = contains(["FIFTEEN_MINUTES", "ONE_HOUR", "SIX_HOURS"], var.guardduty_finding_frequency)
    error_message = "Frequency must be FIFTEEN_MINUTES, ONE_HOUR, or SIX_HOURS."
  }
}

# ============================================================================
# Security Hub Configuration
# ============================================================================

variable "enable_security_hub" {
  description = "Enable AWS Security Hub"
  type        = bool
  default     = true
}

variable "enable_cis_level_1" {
  description = "Enable CIS AWS Foundations Benchmark Level 1"
  type        = bool
  default     = true
}

variable "enable_cis_level_2" {
  description = "Enable CIS AWS Foundations Benchmark Level 2"
  type        = bool
  default     = false
}

variable "enable_pci_dss" {
  description = "Enable PCI-DSS compliance standard"
  type        = bool
  default     = false
}

variable "enable_hipaa" {
  description = "Enable HIPAA compliance checks"
  type        = bool
  default     = false
}

# ============================================================================
# AWS Config Configuration
# ============================================================================

variable "enable_config_rules" {
  description = "Enable AWS Config compliance rules"
  type        = bool
  default     = true
}

# ============================================================================
# CloudTrail Configuration
# ============================================================================

variable "enable_cloudtrail" {
  description = "Enable CloudTrail for audit logging"
  type        = bool
  default     = true
}

variable "cloudtrail_log_retention" {
  description = "CloudWatch Logs retention for CloudTrail (days)"
  type        = number
  default     = 90

  validation {
    condition     = var.cloudtrail_log_retention >= 90
    error_message = "CloudTrail log retention must be at least 90 days (CIS requirement)."
  }
}

variable "cloudwatch_log_retention" {
  description = "Default CloudWatch Logs retention (days)"
  type        = number
  default     = 365
}

# ============================================================================
# KMS Configuration
# ============================================================================

variable "enable_kms_key_rotation" {
  description = "Enable automatic KMS key rotation"
  type        = bool
  default     = true
}

variable "kms_deletion_window" {
  description = "KMS key deletion waiting period (days)"
  type        = number
  default     = 30

  validation {
    condition     = var.kms_deletion_window >= 7 && var.kms_deletion_window <= 30
    error_message = "KMS deletion window must be between 7 and 30 days."
  }
}

variable "enable_ebs_encryption" {
  description = "Enable EBS encryption by default"
  type        = bool
  default     = true
}

# ============================================================================
# S3 Configuration
# ============================================================================

variable "s3_log_lifecycle_glacier" {
  description = "Days before transitioning S3 logs to Glacier"
  type        = number
  default     = 90

  validation {
    condition     = var.s3_log_lifecycle_glacier >= 30
    error_message = "S3 log lifecycle must be at least 30 days."
  }
}

# ============================================================================
# Inspector Configuration
# ============================================================================

variable "enable_inspector" {
  description = "Enable AWS Inspector vulnerability scanning"
  type        = bool
  default     = true
}

# ============================================================================
# Support Role Configuration
# ============================================================================

variable "enable_support_role" {
  description = "Create IAM role for AWS Support access"
  type        = bool
  default     = false
}

# ============================================================================
# Tags
# ============================================================================

variable "additional_tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}