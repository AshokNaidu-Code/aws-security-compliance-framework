variable "environment" {
  description = "Environment name"
  type        = string
}

variable "key_description" {
  description = "Description for the KMS key"
  type        = string
  default     = "KMS key for security compliance"
}
