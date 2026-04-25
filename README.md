# Event-Driven S3 Public Access Corrective Control

This project deploys a real-time, event-driven corrective control that automatically detects and remediates S3 public access exposure using AWS-native services (CloudTrail, EventBridge, Lambda, SNS) and Terraform.

> **Sandbox only.** Do not deploy this in a production account. The Lambda function automatically deletes bucket policies and resets ACLs — this can cause unintended data access disruptions in live environments. Always test in an isolated AWS sandbox account.

## Prerequisites

- **AWS CLI**: Installed and configured with appropriate permissions.
  - To check if AWS CLI is installed: `aws --version`
  - To configure (if not already): `aws configure` (enter your access key, secret key, region, and output format)
  - To verify you're logged in: `aws sts get-caller-identity` (should return your account info without errors)
- Terraform installed (version `~> 1.0`)
- Python 3.13 (runtime: `python3.13`)

## Setup

Use the steps below when deploying from a local environment instead of Terraform Cloud. The AWS CLI is also recommended for testing, as it’s more efficient than manual testing in the AWS Management Console.

1. **Clone or download this repository.**

2. **Edit `variables.tf`** to set your notification email:

   ```terraform
   variable "aws_region" {
      description = "AWS region"
      type        = string
      default     = "YOUR_AWS_REGION"  # Replace with your preferred region
   }

   variable "notification_email" {
      description = "Email address for SNS notifications"
      type        = string
      default     = "your-email@example.com"  # Replace with your email
   }

   variable "aws_profile" {
      description = "AWS CLI profile to use"
      type        = string
      default     = "default" #replace with your profile
   }
   ```

3. **Build the Lambda deployment package before running Terraform.** Terraform does not build the zip automatically - you must create it manually:

   Zip lambda function with dependencies 
   ```bash
   python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt && deactivate
   cd venv/lib/python*/site-packages && zip -r ../../../../lambda_function.zip . && cd - >/dev/null
   zip -g lambda_function.zip lambda_function.py && rm -rf venv
   ```

   The `lambda_function.zip` file must exist before running `terraform apply`.

## Lambda Environment Variables

| Variable        | Required | Description                                                    |
|-----------------|----------|----------------------------------------------------------------|
| `SNS_TOPIC_ARN` | Yes      | ARN of the SNS topic used to send remediation alert emails     |

This variable is set automatically by Terraform during deployment.

## Remediation Scope

This control operates at the **bucket level only**. It remediates:

- **Block Public Access** — re-enables all four Block Public Access settings
- **Bucket policy** — deletes the public bucket policy blocks and only retains private access blocks OR deletes bucket policy if only public access block exist
- **Bucket ACL** — resets the bucket ACL to `private`

It does **not** remediate object-level ACLs. Objects that were individually made public before this control runs will remain public until addressed separately.

## Terraform Providers

Provider versions are managed by Terraform Cloud and pinned in `.terraform.lock.hcl`. The `providers.tf` file configures the AWS provider with the region from `var.aws_region`.

## Terraform Workspace

This project uses Terraform Cloud(Optional):

| Setting      | Value                                  |
|--------------|----------------------------------------|
| Organization | `devsecblueprint`                   |
| Workspace    | `aws-s3-public-access-auto-remediation`|

**Note:** Optional if running locally, comment out `cloud` section from providers.tf for local TF state. 

## Lambda Packaging

   Option 1: Zip lambda function only
   ```bash
   zip lambda_function.zip lambda_function.py
   ```

   Option 2: Zip lambda function with dependencies 
   ```bash
   python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt && deactivate
   cd venv/lib/python*/site-packages && zip -r ../../../../lambda_function.zip . && cd - >/dev/null
   zip -g lambda_function.zip lambda_function.py && rm -rf venv
   ```

## CloudTrail Bucket Lifecycle

The S3 bucket used for CloudTrail logs has a lifecycle policy that automatically expires all objects after **3 days**. This keeps storage costs low and avoids accumulating stale trail data in the sandbox environment.

## Files

- `main.tf`: Main Terraform configuration that orchestrates the modules
- `variables.tf`: Variable definitions with defaults
- `lambda_function.py`: Lambda function code
- `requirements.txt`: Python dependencies
- `README.md`: This file
