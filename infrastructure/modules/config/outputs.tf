output "config_recorder_id" {
  description = "Config recorder ID"
  value       = aws_config_configuration_recorder.main.id
}

output "config_role_arn" {
  description = "Config IAM role ARN"
  value       = aws_iam_role.config.arn
}
