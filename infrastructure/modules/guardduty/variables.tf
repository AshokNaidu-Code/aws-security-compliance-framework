variable "environment" {
  description = "Environment name"
  type        = string
}

variable "finding_publishing_frequency" {
  description = "Frequency of publishing findings"
  type        = string
  default     = "FIFTEEN_MINUTES"
}

variable "enable_s3_protection" {
  description = "Enable S3 protection"
  type        = bool
  default     = true
}

variable "enable_kubernetes_protection" {
  description = "Enable Kubernetes protection"
  type        = bool
  default     = true
}

variable "kms_key_arn" {
  description = "KMS key ARN"
  type        = string
}

variable "sns_topic_arn" {
  description = "SNS topic ARN for alerts"
  type        = string
}
