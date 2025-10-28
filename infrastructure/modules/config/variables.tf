variable "environment" {
  description = "Environment name"
  type        = string
}

variable "config_recorder_name" {
  description = "AWS Config recorder name"
  type        = string
}

variable "s3_bucket_name" {
  description = "S3 bucket name for Config"
  type        = string
}

variable "kms_key_arn" {
  description = "KMS key ARN"
  type        = string
}

variable "sns_topic_arn" {
  description = "SNS topic ARN"
  type        = string
}
    