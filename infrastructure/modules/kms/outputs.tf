output "key_id" {
  description = "KMS key ID"
  value       = aws_kms_key.security_key.key_id
}

output "key_arn" {
  description = "KMS key ARN"
  value       = aws_kms_key.security_key.arn
}

output "key_alias" {
  description = "KMS key alias"
  value       = aws_kms_alias.security_key_alias.name
}
