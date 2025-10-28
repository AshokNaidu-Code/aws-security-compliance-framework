variable "environment" {
  description = "Environment name"
  type        = string
}

variable "s3_bucket_name" {
  description = "S3 bucket name for CloudTrail"
  type        = string
}

variable "kms_key_arn" {
  description = "KMS key ARN"
  type        = string
}

variable "enable_log_validation" {
  description = "Enable log file validation"
  type        = bool
  default     = true
}
