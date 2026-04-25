terraform {
  required_version = "~> 1.0"

  cloud {

    organization = "devsecblueprint"

    workspaces {
      name = "aws-s3-public-access-auto-remediation"
    }
  }
}

provider "aws" {
  region  = var.aws_region
}
