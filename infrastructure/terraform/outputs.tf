output "kms_key_id" {
  description = "KMS key ID for encryption"
  value       = module.kms.key_id
}

output "guardduty_detector_id" {
  description = "GuardDuty detector ID"
  value       = module.guardduty.detector_id
}

output "config_recorder_id" {
  description = "AWS Config recorder ID"
  value       = module.config.config_recorder_id
}

output "cloudtrail_arn" {
  description = "CloudTrail ARN"
  value       = module.cloudtrail.trail_arn
}

output "sns_topic_arn" {
  description = "SNS topic ARN for security alerts"
  value       = aws_sns_topic.security_alerts.arn
}

output "security_operations_role_arn" {
  description = "Security operations role ARN"
  value       = module.iam.security_operations_role_arn
}

output "compliance_auditor_role_arn" {
  description = "Compliance auditor role ARN"
  value       = module.iam.compliance_auditor_role_arn
}
