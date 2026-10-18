# IAM Identity Misconfiguration Test Fixtures
#
# Placed Misconfigurations:
# 1. IAM User with Wildcard (*:*) Administrator Privileges
# 2. IAM User without MFA configured
# 3. IAM User with active Access Key
# 4. Over-privileged IAM Role attached with AdministratorAccess
# 5. Compliant baseline IAM role (least-privilege read-only)
#
# Free Tier Safety:
# - All IAM users, groups, roles, and policies are 100% FREE in AWS.

# -----------------------------------------------------------------------------
# Misconfigured User 1: Wildcard Admin Policy (*:*) & No MFA
# -----------------------------------------------------------------------------
resource "aws_iam_user" "wildcard_user" {
  name = "${var.project_prefix}-wildcard-admin-user"
  path = "/cloudguard-test/"
}

resource "aws_iam_policy" "wildcard_policy" {
  name        = "${var.project_prefix}-wildcard-policy"
  description = "Deliberate insecure wildcard admin policy for testing CloudGuard detection"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_user_policy_attachment" "attach_wildcard" {
  user       = aws_iam_user.wildcard_user.name
  policy_arn = aws_iam_policy.wildcard_policy.arn
}

# -----------------------------------------------------------------------------
# Misconfigured User 2: Active Access Key & No MFA
# -----------------------------------------------------------------------------
resource "aws_iam_user" "mfa_missing_user" {
  name = "${var.project_prefix}-no-mfa-user"
  path = "/cloudguard-test/"
}

resource "aws_iam_access_key" "test_access_key" {
  user = aws_iam_user.mfa_missing_user.name
}

# -----------------------------------------------------------------------------
# Misconfigured Role 1: Over-privileged Role with Full Admin Access
# -----------------------------------------------------------------------------
resource "aws_iam_role" "overprivileged_role" {
  name = "${var.project_prefix}-overprivileged-role"
  path = "/cloudguard-test/"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_admin_to_role" {
  role       = aws_iam_role.overprivileged_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# -----------------------------------------------------------------------------
# Compliant Baseline Role: Scoped Least-Privilege (Should produce 0 findings)
# -----------------------------------------------------------------------------
resource "aws_iam_role" "compliant_scoped_role" {
  name = "${var.project_prefix}-compliant-scoped-role"
  path = "/cloudguard-test/"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_policy" "scoped_readonly_policy" {
  name        = "${var.project_prefix}-scoped-readonly"
  description = "Scoped read-only policy compliant with least-privilege"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetBucketLocation",
          "s3:ListBucket"
        ]
        Resource = "arn:aws:s3:::my-test-bucket-example"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_scoped" {
  role       = aws_iam_role.compliant_scoped_role.name
  policy_arn = aws_iam_policy.scoped_readonly_policy.arn
}
