# S3 Storage Misconfiguration Test Fixtures
#
# Placed Misconfigurations:
# 1. Bucket with Public Policy (s3:GetObject open to Principal "*")
# 2. Bucket with Block Public Access completely disabled
# 3. Bucket with Public ACL enabled
# 4. Compliant baseline bucket (all BPA enabled, SSE enabled) for false-positive validation.
#
# Free Tier Safety:
# - Empty S3 buckets carry $0.00 storage cost.
# - Free tier includes 5GB standard storage and 20,000 GET requests.

resource "random_string" "s3_suffix" {
  length  = 6
  special = false
  upper   = false
}

# -----------------------------------------------------------------------------
# Misconfigured Bucket 1: Public Bucket Policy
# -----------------------------------------------------------------------------
resource "aws_s3_bucket" "public_policy_bucket" {
  bucket        = "${var.project_prefix}-pub-policy-${random_string.s3_suffix.result}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "public_policy_bpa" {
  bucket = aws_s3_bucket.public_policy_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "public_read_policy" {
  bucket     = aws_s3_bucket.public_policy_bucket.id
  depends_on = [aws_s3_bucket_public_access_block.public_policy_bpa]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.public_policy_bucket.arn}/*"
      }
    ]
  })
}

# -----------------------------------------------------------------------------
# Misconfigured Bucket 2: Block Public Access Disabled & Public ACL Enabled
# -----------------------------------------------------------------------------
resource "aws_s3_bucket" "public_acl_bucket" {
  bucket        = "${var.project_prefix}-pub-acl-${random_string.s3_suffix.result}"
  force_destroy = true
}

resource "aws_s3_bucket_ownership_controls" "acl_ownership" {
  bucket = aws_s3_bucket.public_acl_bucket.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_public_access_block" "disabled_bpa" {
  bucket = aws_s3_bucket.public_acl_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_acl" "public_read_acl" {
  bucket = aws_s3_bucket.public_acl_bucket.id
  acl    = "public-read"

  depends_on = [
    aws_s3_bucket_ownership_controls.acl_ownership,
    aws_s3_bucket_public_access_block.disabled_bpa
  ]
}

# -----------------------------------------------------------------------------
# Misconfigured Bucket 3: Missing Explicit Default Encryption
# -----------------------------------------------------------------------------
resource "aws_s3_bucket" "unencrypted_bucket" {
  bucket        = "${var.project_prefix}-no-encrypt-${random_string.s3_suffix.result}"
  force_destroy = true
}

# -----------------------------------------------------------------------------
# Compliant Baseline Bucket (Should produce 0 findings)
# -----------------------------------------------------------------------------
resource "aws_s3_bucket" "compliant_secure_bucket" {
  bucket        = "${var.project_prefix}-secure-baseline-${random_string.s3_suffix.result}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "compliant_bpa" {
  bucket = aws_s3_bucket.compliant_secure_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "compliant_encryption" {
  bucket = aws_s3_bucket.compliant_secure_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
