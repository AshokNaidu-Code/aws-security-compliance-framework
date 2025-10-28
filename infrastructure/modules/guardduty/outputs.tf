output "detector_id" {
  description = "GuardDuty detector ID"
  value       = aws_guardduty_detector.main.id
}

output "findings_bucket_name" {
  description = "S3 bucket name for GuardDuty findings"
  value       = aws_s3_bucket.guardduty_findings.id
}
