# ---------- ENABLE CLOUDTRAIL ---------- 
resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "trail_bucket" {
  bucket        = "aws-s3-public-access-trail-bucket-${random_id.bucket_suffix.hex}"
  force_destroy = true
}

resource "aws_s3_bucket_lifecycle_configuration" "trail_bucket_lifecycle" {
  bucket = aws_s3_bucket.trail_bucket.id

  rule {
    id     = "expire-all-objects"
    status = "Enabled"

    filter {}

    expiration {
      days = 3
    }
  }
}

resource "aws_s3_bucket_policy" "trail_bucket_policy" {
  bucket = aws_s3_bucket.trail_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.trail_bucket.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.trail_bucket.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

resource "aws_cloudtrail" "s3_trail" {
  name                          = "s3-public-access-trail"
  s3_bucket_name                = aws_s3_bucket.trail_bucket.bucket
  enable_logging                = true
  include_global_service_events = false
  is_multi_region_trail         = false
  depends_on                    = [aws_s3_bucket_policy.trail_bucket_policy]

  event_selector {
    read_write_type           = "All"
    include_management_events = true
    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"]
    }
  }
}

resource "aws_sns_topic" "s3_public_remediate_alerts" {
  name = "s3-public-access-alerts"
}

resource "aws_sns_topic_subscription" "email_subscription" {
  topic_arn = aws_sns_topic.s3_public_remediate_alerts.arn
  protocol  = "email"
  endpoint  = var.notification_email
}

# ---------- CREATE IAM ROLE FOR LAMBDA ----------
resource "aws_iam_role" "lambda_role" {
  name = "s3-public-access-remediator-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_policy" "lambda_policy" {
  name        = "s3-public-access-remediator-lambda-policy"
  description = "Lambda permissions to check S3 buckets and send SNS alerts"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "AllowS3ReadOnly"
        Effect = "Allow"
        Action = [
          "s3:GetBucketAcl",
          "s3:GetBucketPolicy",
          "s3:GetBucketPolicyStatus",
          "s3:GetBucketPublicAccessBlock"
        ]
        Resource = "*"
      },
      {
        Sid = "AllowS3WriteAccess"
        Effect = "Allow"
        Action = [
          "s3:PutBucketPublicAccessBlock",
          "s3:PutBucketPolicy",
          "s3:PutBucketAcl",
          "s3:DeleteBucketPolicy",
        ]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.s3_public_remediate_alerts.arn
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_attach" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.lambda_policy.arn
}

# ---------- CREATE THE LAMBDA FUNCTION ----------
resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/s3-public-access-remediator"
  retention_in_days = 7
}

resource "aws_lambda_function" "s3_public_access_remediator" {
  function_name = "s3-public-access-remediator"
  runtime       = "python3.13"
  role          = aws_iam_role.lambda_role.arn
  handler       = "lambda_function.lambda_handler"

  filename         = "lambda_function.zip"
  source_code_hash = filebase64sha256("lambda_function.zip")

  timeout = 30

  environment {
    variables = {
      SNS_TOPIC_ARN         = aws_sns_topic.s3_public_remediate_alerts.arn
    }
  }

  depends_on = [aws_cloudwatch_log_group.lambda_logs]
}

# ---------- CREATE EVENTBRIDGE RULE ----------
resource "aws_cloudwatch_event_rule" "s3_events_rule" {
  name        = "s3-public-access-remediator-rule"
  description = "Trigger Lambda for S3 bucket public access changes"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName = [
        "PutBucketPolicy",
        "PutBucketAcl",
        "PutBucketPublicAccessBlock",
        "DeletePublicAccessBlock"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.s3_events_rule.name
  target_id = "LambdaTarget"
  arn       = aws_lambda_function.s3_public_access_remediator.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.s3_public_access_remediator.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.s3_events_rule.arn
}




