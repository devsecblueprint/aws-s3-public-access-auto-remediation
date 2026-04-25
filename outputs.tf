output "lambda_function_arn" {
  description = "ARN of the S3 security checker Lambda function"
  value       = aws_lambda_function.s3_public_access_remediator.arn
}

output "sns_topic_arn" {
  description = "ARN of the S3 public access alerts SNS topic"
  value       = aws_sns_topic.s3_public_remediate_alerts.arn
}

output "cloudtrail_name" {
  description = "Name of the S3 public access CloudTrail"
  value       = aws_cloudtrail.s3_trail.name
}

output "cloudwatch_log_group_name" {
  description = "Name of the Lambda CloudWatch Log Group"
  value       = aws_cloudwatch_log_group.lambda_logs.name
}

