output "trail_arn" {
  description = "CloudTrail ARN"
  value       = aws_cloudtrail.main.arn
}

output "trail_bucket" {
  description = "CloudTrail S3 bucket"
  value       = aws_s3_bucket.cloudtrail.id
}
