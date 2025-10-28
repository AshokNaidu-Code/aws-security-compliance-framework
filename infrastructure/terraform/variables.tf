variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "prod"
}

variable "owner_email" {
  description = "Owner email for tagging"
  type        = string
}

variable "enable_mfa_enforcement" {
  description = "Enable MFA enforcement for IAM users"
  type        = bool
  default     = true
}

variable "guardduty_finding_publishing_frequency" {
  description = "Frequency of GuardDuty findings (FIFTEEN_MINUTES, ONE_HOUR, SIX_HOURS)"
  type        = string
  default     = "FIFTEEN_MINUTES"
}

variable "cloudtrail_s3_bucket_name" {
  description = "S3 bucket name for CloudTrail logs"
  type        = string
}

variable "enable_s3_protection" {
  description = "Enable S3 protection in GuardDuty"
  type        = bool
  default     = true
}

variable "enable_kubernetes_protection" {
  description = "Enable Kubernetes protection in GuardDuty"
  type        = bool
  default     = true
}

variable "config_recorder_name" {
  description = "Name of the AWS Config recorder"
  type        = string
  default     = "security-compliance-recorder"
}

variable "sns_email_endpoints" {
  description = "List of email addresses for SNS notifications"
  type        = list(string)
  default     = []
}
