# Input Variables for CloudGuard Deliberate Misconfiguration Testbed

variable "aws_region" {
  description = "Target AWS region for deploying test resources"
  type        = string
  default     = "ap-south-1"
}

variable "aws_profile" {
  description = "AWS CLI profile name configured with test credentials"
  type        = string
  default     = "cloudguard"
}

variable "project_prefix" {
  description = "Naming prefix applied to all planted resources for easy identification and cleanup"
  type        = string
  default     = "cloudguard-test"
}
