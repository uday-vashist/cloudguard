"""
CloudGuard: AWS Security Misconfiguration Detection and Risk Prioritization System
Main CLI Entry Point.

How to run:
    python -m cloudguard.main
    python -m cloudguard.main --smoke-test
"""

import argparse
import sys
from cloudguard.aws_session import (
    DEFAULT_PROFILE,
    DEFAULT_REGION,
    get_client,
    ReadOnlyViolationError,
)
from botocore.exceptions import ProfileNotFound, NoCredentialsError, ClientError


def run_smoke_test(profile: str, region: str) -> int:
    """
    Performs STS get_caller_identity check using the read-only client wrapper.
    Ensures safe authentication to AWS without exposing credentials.
    """
    print("=" * 60)
    print(" CloudGuard CLI - Authentication & Smoke Check")
    print(f" Profile: {profile} | Region: {region}")
    print("=" * 60)

    try:
        sts = get_client("sts", region_name=region, profile_name=profile)
        identity = sts.get_caller_identity()
        print("\n[OK] AWS Authentication Successful!")
        print(f"  Account ID : {identity.get('Account')}")
        print(f"  Arn        : {identity.get('Arn')}")
        print(f"  UserId     : {identity.get('UserId')}")
        print("\nCloudGuard read-only session is operational and ready for audit.")
        return 0
    except ProfileNotFound:
        print(f"\n[ERROR] AWS profile '{profile}' was not found in your AWS configuration.")
        print("To configure your AWS profile, run:")
        print(f"    aws configure --profile {profile}")
        print("Enter your Access Key ID, Secret Access Key, and set default region to 'ap-south-1'.")
        return 1
    except NoCredentialsError:
        print(f"\n[ERROR] No AWS credentials found for profile '{profile}'.")
        print(f"Please run 'aws configure --profile {profile}'.")
        return 1
    except ClientError as e:
        print(f"\n[ERROR] AWS Error during STS call: {e}")
        return 1
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {e}")
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="CloudGuard - AWS Security Misconfiguration Detection and Risk Prioritization"
    )
    parser.add_argument(
        "--profile",
        default=DEFAULT_PROFILE,
        help=f"AWS CLI profile name (default: {DEFAULT_PROFILE})"
    )
    parser.add_argument(
        "--region",
        default=DEFAULT_REGION,
        help=f"AWS region to audit (default: {DEFAULT_REGION})"
    )
    parser.add_argument(
        "--smoke-test",
        action="store_true",
        help="Run STS get_caller_identity smoke test to verify authentication."
    )
    parser.add_argument(
        "--output",
        default="reports/audit_report.html",
        help="Path for generated HTML audit report (default: reports/audit_report.html)"
    )

    args = parser.parse_args()

    # Stage 1: Smoke test or initial readiness check
    if args.smoke_test:
        return run_smoke_test(args.profile, args.region)

    print("=" * 60)
    print(" CloudGuard - AWS Security Audit Tool")
    print(f" Profile: {args.profile} | Region: {args.region}")
    print("=" * 60)
    print("\n[INFO] CloudGuard core framework initialized (Stage 1).")
    print("Run with --smoke-test to verify AWS STS caller identity.")
    print("Scanners (S3, IAM, Security Groups, Monitoring) are scheduled for Stages 3 & 4.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
