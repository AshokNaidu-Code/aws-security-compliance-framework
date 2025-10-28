output "security_admins_group_name" {
  description = "Security admins group name"
  value       = aws_iam_group.security_admins.name
}

output "security_operations_role_arn" {
  description = "Security operations role ARN"
  value       = aws_iam_role.security_operations.arn
}

output "compliance_auditor_role_arn" {
  description = "Compliance auditor role ARN"
  value       = aws_iam_role.compliance_auditor.arn
}
