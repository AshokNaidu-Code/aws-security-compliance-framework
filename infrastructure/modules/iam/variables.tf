variable "environment" {
  description = "Environment name"
  type        = string
}

variable "enable_mfa_enforcement" {
  description = "Enable MFA enforcement"
  type        = bool
  default     = true
}

variable "kms_key_arn" {
  description = "KMS key ARN for encryption"
  type        = string
}
