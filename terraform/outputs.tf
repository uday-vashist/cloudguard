
# Terraform Outputs for CloudGuard Deliberately Misconfigured Testbed

output "s3_public_policy_bucket" {
  description = "Name of bucket with public policy"
  value       = aws_s3_bucket.public_policy_bucket.bucket
}

output "s3_public_acl_bucket" {
  description = "Name of bucket with public ACL and disabled BPA"
  value       = aws_s3_bucket.public_acl_bucket.bucket
}

output "s3_unencrypted_bucket" {
  description = "Name of unencrypted bucket"
  value       = aws_s3_bucket.unencrypted_bucket.bucket
}

output "s3_compliant_bucket" {
  description = "Name of compliant baseline bucket (should NOT produce findings)"
  value       = aws_s3_bucket.compliant_secure_bucket.bucket
}

output "iam_wildcard_user" {
  description = "IAM user with wildcard *:* admin policy"
  value       = aws_iam_user.wildcard_user.name
}

output "iam_no_mfa_user" {
  description = "IAM user with access key and no MFA"
  value       = aws_iam_user.mfa_missing_user.name
}

output "iam_overprivileged_role" {
  description = "IAM role with AdministratorAccess"
  value       = aws_iam_role.overprivileged_role.name
}

output "sg_open_ssh_id" {
  description = "Security group with port 22 open to 0.0.0.0/0"
  value       = aws_security_group.open_ssh_sg.id
}

output "sg_open_rdp_id" {
  description = "Security group with port 3389 open to 0.0.0.0/0"
  value       = aws_security_group.open_rdp_sg.id
}

output "sg_open_db_id" {
  description = "Security group with database ports open to 0.0.0.0/0"
  value       = aws_security_group.open_db_sg.id
}

output "sg_compliant_id" {
  description = "Compliant security group (should NOT produce high/critical findings)"
  value       = aws_security_group.compliant_web_sg.id
}

output "monitoring_insecure_trail" {
  description = "Name of single-region CloudTrail with validation disabled"
  value       = aws_cloudtrail.insecure_test_trail.name
}
