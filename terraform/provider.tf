# Terraform Provider Configuration for CloudGuard Test Environment
#
# VIVA EXPLANATION:
# Why Terraform for testing?
# In cybersecurity auditing, we need a reproducible, deterministic test environment
# where we know the exact ground truth of vulnerabilities planted. This allows us to
# calculate mathematical Recall (caught issues / total planted issues) and Precision.
#
# SAFETY NOTICE:
# - All resources planted here stay strictly within AWS Free Tier.
# - No compute instances (EC2) or databases (RDS) are launched.
# - CloudGuard only audits security group definitions, IAM policies, S3 metadata,
#   and CloudTrail settings. Total expected AWS cost: $0.00.

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile

  default_tags {
    tags = {
      Project     = "CloudGuard-Testbed"
      Environment = "Testing"
      ManagedBy   = "Terraform"
      Auditor     = "CSE-MiniProject"
    }
  }
}
