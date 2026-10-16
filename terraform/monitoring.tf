# Monitoring Misconfiguration Test Fixtures
#
# Placed Misconfigurations:
# 1. CloudTrail trail is single-region only (is_multi_region_trail = false)
# 2. CloudTrail trail has Log File Validation disabled (enable_log_file_validation = false)
# 3. Absence of CloudWatch metric alarms for critical security events
#
# Free Tier Safety:
# - AWS CloudTrail delivers ONE copy of management events to an S3 bucket for FREE.
# - Log storage for testing is <1 MB (within 5GB Free Tier).

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "trail_bucket" {
  bucket        = "${var.project_prefix}-trail-logs-${random_string.s3_suffix.result}"
  force_destroy = true
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
        Resource = "${aws_s3_bucket.trail_bucket.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

# -----------------------------------------------------------------------------
# Misconfigured Trail: Single-Region & Log File Validation Disabled
# -----------------------------------------------------------------------------
resource "aws_cloudtrail" "insecure_test_trail" {
  name                          = "${var.project_prefix}-insecure-trail"
  s3_bucket_name                = aws_s3_bucket.trail_bucket.id
  include_global_service_events = false
  is_multi_region_trail         = false # INSECURE: Fails CIS Benchmark (must be multi-region)
  enable_log_file_validation    = false # INSECURE: Fails CIS Benchmark (log tampering possible)
  enable_logging                = true

  depends_on = [aws_s3_bucket_policy.trail_bucket_policy]
}
