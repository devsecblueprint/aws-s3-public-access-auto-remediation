# Variables
variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "notification_email" {
  description = "Email address for SNS notifications"
  type        = string
  default     = "your-email@example.com"
}