"""
CloudGuard: AWS Security Misconfiguration Detection and Risk Prioritization System
Main CLI Entry Point & Pipeline Orchestrator.

How to run:
    python -m cloudguard.main
    python -m cloudguard.main --smoke-test
    python -m cloudguard.main --profile cloudguard --region ap-south-1 --output reports/audit_report.html
"""

import argparse
import sys
from typing import List, Optional

from botocore.exceptions import ProfileNotFound, NoCredentialsError, ClientError

from cloudguard.aws_session import (
    DEFAULT_PROFILE,
    DEFAULT_REGION,
    CloudGuardSession,
    get_session,
    get_client,
    ReadOnlyViolationError,
)
from cloudguard.scanners.s3_scanner import scan_s3
from cloudguard.scanners.iam_scanner import scan_iam
from cloudguard.scanners.sg_scanner import scan_security_groups
from cloudguard.scanners.monitoring_scanner import scan_monitoring
from cloudguard.cis_mapping import tag_findings_with_cis
from cloudguard.scoring import score_and_rank_findings
from cloudguard.report import generate_html_report


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


def run_audit(
    profile: str = DEFAULT_PROFILE,
    region: str = DEFAULT_REGION,
    output_path: str = "reports/audit_report.html",
    session: Optional[CloudGuardSession] = None,
) -> int:
    """
    Executes the end-to-end CloudGuard audit pipeline:
    1. Authenticates via read-only CloudGuardSession.
    2. Runs S3, IAM, Security Group, and Monitoring scanners using wrapped read-only clients.
    3. Tags findings with CIS AWS Foundations Benchmark controls.
    4. Calculates 3-factor multiplicative risk scores and ranks findings.
    5. Renders self-contained HTML audit report.
    6. Summarizes findings to stdout.

    Returns:
        0 on success (or clean audit), 1 on error or incomplete audit.
    """
    print("=" * 60)
    print(" CloudGuard - AWS Security Audit Tool")
    print(f" Profile: {profile} | Region: {region}")
    print("=" * 60)

    # 1. Initialize AWS read-only session
    try:
        cg_session = session or get_session(profile_name=profile, region_name=region)
    except (ProfileNotFound, RuntimeError) as e:
        print(f"\n[ERROR] AWS profile '{profile}' was not found in your configuration.")
        print(f"To configure your AWS profile, run:")
        print(f"    aws configure --profile {profile}")
        return 1
    except NoCredentialsError:
        print(f"\n[ERROR] No AWS credentials found for profile '{profile}'.")
        print(f"Please run 'aws configure --profile {profile}'.")
        return 1
    except Exception as e:
        print(f"\n[ERROR] Failed to initialize AWS session: {e}")
        return 1

    all_findings = []
    failed_scanners = []

    # 2. Execute scanners using wrapped read-only clients
    # Scanner 1: S3 Storage
    print("\n[1/4] Auditing Amazon S3 storage...")
    try:
        s3_client = cg_session.client("s3")
        s3_findings = scan_s3(client=s3_client, region_name=region)
        all_findings.extend(s3_findings)
        print(f"      -> Completed. Found {len(s3_findings)} S3 issue(s)")
    except Exception as e:
        print(f"      -> [ERROR] S3 scanner failed: {e}")
        failed_scanners.append(("S3 Storage", str(e)))

    # Scanner 2: IAM Identity
    print("\n[2/4] Auditing AWS IAM identity and access...")
    try:
        iam_client = cg_session.client("iam")
        iam_findings = scan_iam(client=iam_client)
        all_findings.extend(iam_findings)
        print(f"      -> Completed. Found {len(iam_findings)} IAM issue(s)")
    except Exception as e:
        print(f"      -> [ERROR] IAM scanner failed: {e}")
        failed_scanners.append(("IAM Identity", str(e)))

    # Scanner 3: Security Groups
    print("\n[3/4] Auditing EC2 Security Groups network perimeter...")
    try:
        ec2_client = cg_session.client("ec2")
        sg_findings = scan_security_groups(client=ec2_client, region_name=region)
        all_findings.extend(sg_findings)
        print(f"      -> Completed. Found {len(sg_findings)} Security Group issue(s)")
    except Exception as e:
        print(f"      -> [ERROR] Security Group scanner failed: {e}")
        failed_scanners.append(("Security Groups", str(e)))

    # Scanner 4: Observability & Monitoring
    print("\n[4/4] Auditing Observability (CloudTrail & CloudWatch)...")
    try:
        ct_client = cg_session.client("cloudtrail")
        cw_client = cg_session.client("cloudwatch")
        mon_findings = scan_monitoring(
            cloudtrail_client=ct_client,
            cloudwatch_client=cw_client,
            region_name=region,
        )
        all_findings.extend(mon_findings)
        print(f"      -> Completed. Found {len(mon_findings)} Monitoring issue(s)")
    except Exception as e:
        print(f"      -> [ERROR] Monitoring scanner failed: {e}")
        failed_scanners.append(("Monitoring", str(e)))

    # 3. Handle scanner failure boundaries (Prevent misleading clean-audit reports)
    if failed_scanners:
        print("\n" + "!" * 60)
        print(" [WARNING] AUDIT INCOMPLETE: One or more scanners failed!")
        for s_name, err in failed_scanners:
            print(f"   - {s_name}: {err}")
        print("!" * 60)

        if not all_findings:
            print("\n[ERROR] Audit incomplete and zero findings gathered due to scanner failure(s).")
            print("Report generation skipped to prevent generating a misleading clean-audit report.")
            return 1

        print("\n[WARN] Generating partial report containing findings from successful scanner(s).")
        print("Note: This report does NOT represent a complete audit.")

    # 4. Enrich findings with official CIS Benchmark control mapping
    tagged_findings = tag_findings_with_cis(all_findings)

    # 5. Score and rank findings by risk score descending
    ranked_findings = score_and_rank_findings(tagged_findings)

    # 6. Generate HTML report
    failed_scanner_names = [name for name, _ in failed_scanners]
    try:
        report_path = generate_html_report(
            findings=ranked_findings,
            output_path=output_path,
            profile=profile,
            region=region,
            failed_scanners=failed_scanner_names if failed_scanners else None,
        )
    except Exception as e:
        print(f"\n[ERROR] Failed to generate HTML report: {e}")
        return 1

    # 7. Print terminal summary
    print("\n" + "=" * 60)
    print(" CloudGuard Audit Summary")
    print("=" * 60)
    print(f" Total Findings : {len(ranked_findings)}")
    crit_count = sum(1 for f in ranked_findings if f.severity == "CRITICAL")
    high_count = sum(1 for f in ranked_findings if f.severity == "HIGH")
    med_count = sum(1 for f in ranked_findings if f.severity == "MEDIUM")
    low_count = sum(1 for f in ranked_findings if f.severity == "LOW")
    print(f"   - CRITICAL   : {crit_count}")
    print(f"   - HIGH       : {high_count}")
    print(f"   - MEDIUM     : {med_count}")
    print(f"   - LOW        : {low_count}")
    if ranked_findings:
        print(f" Peak Risk Score: {ranked_findings[0].risk_score:.1f} / 50.0")
    else:
        print(" Posture Status : Clean (Zero misconfigurations detected)")
    print(f"\n[OK] HTML Report: {report_path}")
    print("=" * 60)

    # Return 1 if any scanner failed, else 0
    return 1 if failed_scanners else 0


def main(argv: Optional[List[str]] = None) -> int:
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

    args = parser.parse_args(argv)

    # Smoke test mode
    if args.smoke_test:
        return run_smoke_test(args.profile, args.region)

    # Full audit pipeline mode
    return run_audit(
        profile=args.profile,
        region=args.region,
        output_path=args.output,
    )


if __name__ == "__main__":
    sys.exit(main())
