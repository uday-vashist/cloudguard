"""
CloudGuard S3 Storage Security Scanner.

Audits Amazon S3 storage resources against security misconfigurations:
1. Public Bucket Policy (Policy granting public access to Principal "*")
2. Block Public Access (BPA) Disabled
3. Public Bucket ACLs (Grants to AllUsers or AuthenticatedUsers)
4. Missing Default Server-Side Encryption (SSE)

VIVA CONCEPTS:
- Principle: S3 buckets must be private by default. Data leaks often occur due to
  misconfigured bucket policies, legacy ACLs, or disabled Block Public Access.
- Read-Only Compliance: Only calls list_buckets, get_bucket_policy_status,
  get_bucket_policy, get_public_access_block, get_bucket_acl, get_bucket_encryption,
  and get_bucket_location.
"""

import json
from typing import Any, Dict, List, Optional
from botocore.exceptions import ClientError
from cloudguard.aws_session import get_client, ReadOnlyClientWrapper
from cloudguard.models import Finding

# Well-known public grantee URIs in AWS S3 ACLs
PUBLIC_ALL_USERS_URI = "http://acs.amazonaws.com/groups/global/AllUsers"
PUBLIC_AUTH_USERS_URI = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"


def check_bucket_policy(s3_client: Any, bucket_name: str, region: str) -> Optional[Finding]:
    """
    Check if the bucket policy grants public access.
    Uses s3.get_bucket_policy_status and falls back to inspecting policy statements.
    """
    # 1. Try get_bucket_policy_status (boto3 official helper)
    try:
        status_resp = s3_client.get_bucket_policy_status(Bucket=bucket_name)
        if status_resp.get("PolicyStatus", {}).get("IsPublic", False):
            return Finding(
                id=f"s3-public-policy-{bucket_name}",
                check_name="S3 Bucket Public Access via Policy",
                resource_type="AWS::S3::Bucket",
                resource_id=bucket_name,
                region=region,
                severity="CRITICAL",
                exposure="PUBLIC",
                sensitivity="HIGH",
                evidence={"PolicyStatus": status_resp.get("PolicyStatus")},
                remediation=(
                    f"aws s3api delete-bucket-policy --bucket {bucket_name}\n"
                    f"Or apply S3 Block Public Access to prevent public policies."
                )
            )
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        # NoSuchBucketPolicy is normal for buckets without policy
        if error_code not in ("NoSuchBucketPolicy", "AccessDenied"):
            pass

    # 2. Inspect raw bucket policy if available
    try:
        policy_resp = s3_client.get_bucket_policy(Bucket=bucket_name)
        raw_policy = policy_resp.get("Policy", "{}")
        policy_doc = json.loads(raw_policy) if isinstance(raw_policy, str) else raw_policy

        for stmt in policy_doc.get("Statement", []):
            if stmt.get("Effect") == "Allow":
                principal = stmt.get("Principal")
                if principal == "*" or principal == {"AWS": "*"}:
                    return Finding(
                        id=f"s3-public-policy-{bucket_name}",
                        check_name="S3 Bucket Public Access via Policy",
                        resource_type="AWS::S3::Bucket",
                        resource_id=bucket_name,
                        region=region,
                        severity="CRITICAL",
                        exposure="PUBLIC",
                        sensitivity="HIGH",
                        evidence={"Statement": stmt},
                        remediation=f"Remove wildcard Principal '*' from bucket policy for {bucket_name}."
                    )
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code not in ("NoSuchBucketPolicy", "AccessDenied"):
            pass

    return None


def check_public_access_block(s3_client: Any, bucket_name: str, region: str) -> Optional[Finding]:
    """
    Check if S3 Block Public Access (BPA) is enabled for all 4 security settings:
    - BlockPublicAcls
    - IgnorePublicAcls
    - BlockPublicPolicy
    - RestrictPublicBuckets
    """
    try:
        bpa_resp = s3_client.get_public_access_block(Bucket=bucket_name)
        config = bpa_resp.get("PublicAccessBlockConfiguration", {})

        disabled_settings = [k for k, v in config.items() if v is False]

        if disabled_settings or not config:
            return Finding(
                id=f"s3-bpa-disabled-{bucket_name}",
                check_name="S3 Bucket Block Public Access Disabled",
                resource_type="AWS::S3::Bucket",
                resource_id=bucket_name,
                region=region,
                severity="HIGH",
                exposure="PUBLIC",
                sensitivity="HIGH",
                evidence={"PublicAccessBlockConfiguration": config, "DisabledSettings": disabled_settings},
                remediation=(
                    f"aws s3api put-public-access-block --bucket {bucket_name} "
                    f"--public-access-block-configuration "
                    f"BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
                )
            )
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code in ("NoSuchPublicAccessBlockConfiguration", "NoSuchBucket"):
            return Finding(
                id=f"s3-bpa-disabled-{bucket_name}",
                check_name="S3 Bucket Block Public Access Disabled",
                resource_type="AWS::S3::Bucket",
                resource_id=bucket_name,
                region=region,
                severity="HIGH",
                exposure="PUBLIC",
                sensitivity="HIGH",
                evidence={"Error": "No PublicAccessBlock configuration exists on bucket"},
                remediation=(
                    f"aws s3api put-public-access-block --bucket {bucket_name} "
                    f"--public-access-block-configuration "
                    f"BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
                )
            )
    return None


def check_bucket_acl(s3_client: Any, bucket_name: str, region: str) -> Optional[Finding]:
    """
    Check if the bucket ACL grants permissions to the public (AllUsers or AuthenticatedUsers).
    """
    try:
        acl_resp = s3_client.get_bucket_acl(Bucket=bucket_name)
        public_grants = []
        for grant in acl_resp.get("Grants", []):
            grantee = grant.get("Grantee", {})
            uri = grantee.get("URI", "")
            if uri in (PUBLIC_ALL_USERS_URI, PUBLIC_AUTH_USERS_URI):
                public_grants.append({
                    "Permission": grant.get("Permission"),
                    "Grantee": uri
                })

        if public_grants:
            return Finding(
                id=f"s3-public-acl-{bucket_name}",
                check_name="S3 Bucket Public Access via ACL",
                resource_type="AWS::S3::Bucket",
                resource_id=bucket_name,
                region=region,
                severity="HIGH",
                exposure="PUBLIC",
                sensitivity="HIGH",
                evidence={"PublicGrants": public_grants},
                remediation=(
                    f"aws s3api put-bucket-acl --bucket {bucket_name} --acl private\n"
                    f"Enforce S3 Object Ownership (BucketOwnerEnforced) to disable ACLs."
                )
            )
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code != "AccessDenied":
            pass
    return None


def check_bucket_encryption(s3_client: Any, bucket_name: str, region: str) -> Optional[Finding]:
    """
    Check if default Server-Side Encryption (SSE) is configured.
    """
    try:
        enc_resp = s3_client.get_bucket_encryption(Bucket=bucket_name)
        rules = enc_resp.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        if not rules:
            return Finding(
                id=f"s3-missing-encryption-{bucket_name}",
                check_name="S3 Bucket Missing Default Encryption",
                resource_type="AWS::S3::Bucket",
                resource_id=bucket_name,
                region=region,
                severity="HIGH",
                exposure="INTERNAL",
                sensitivity="MEDIUM",
                evidence={"ServerSideEncryptionConfiguration": enc_resp},
                remediation=(
                    f"aws s3api put-bucket-encryption --bucket {bucket_name} "
                    f"--server-side-encryption-configuration "
                    f"'{{\"Rules\": [{{\"ApplyServerSideEncryptionByDefault\": {{\"SSEAlgorithm\": \"AES256\"}}}}]}}'"
                )
            )
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code in ("ServerSideEncryptionConfigurationNotFoundError", "NoSuchBucket"):
            return Finding(
                id=f"s3-missing-encryption-{bucket_name}",
                check_name="S3 Bucket Missing Default Encryption",
                resource_type="AWS::S3::Bucket",
                resource_id=bucket_name,
                region=region,
                severity="HIGH",
                exposure="INTERNAL",
                sensitivity="MEDIUM",
                evidence={"Error": "No ServerSideEncryptionConfiguration found"},
                remediation=(
                    f"aws s3api put-bucket-encryption --bucket {bucket_name} "
                    f"--server-side-encryption-configuration "
                    f"'{{\"Rules\": [{{\"ApplyServerSideEncryptionByDefault\": {{\"SSEAlgorithm\": \"AES256\"}}}}]}}'"
                )
            )
    return None


def scan_s3(client: Optional[Any] = None, region_name: str = "ap-south-1") -> List[Finding]:
    """
    Main S3 scanner entry point.
    Audits all S3 buckets accessible by the credentials.
    """
    s3_client = client or get_client("s3", region_name=region_name)
    findings: List[Finding] = []

    try:
        buckets_resp = s3_client.list_buckets()
        buckets = buckets_resp.get("Buckets", [])
    except ClientError as e:
        print(f"[ERROR] S3 list_buckets failed (Unable to evaluate S3 storage): {e}")
        raise

    for b in buckets:
        bucket_name = b.get("Name", "")
        if not bucket_name:
            continue

        # Determine bucket region (defaults to us-east-1 if None)
        try:
            loc_resp = s3_client.get_bucket_location(Bucket=bucket_name)
            loc = loc_resp.get("LocationConstraint")
            bucket_region = loc if loc else "us-east-1"
        except ClientError:
            bucket_region = region_name

        # Run checks on this bucket
        f_policy = check_bucket_policy(s3_client, bucket_name, bucket_region)
        if f_policy:
            findings.append(f_policy)

        f_bpa = check_public_access_block(s3_client, bucket_name, bucket_region)
        if f_bpa:
            findings.append(f_bpa)

        f_acl = check_bucket_acl(s3_client, bucket_name, bucket_region)
        if f_acl:
            findings.append(f_acl)

        f_enc = check_bucket_encryption(s3_client, bucket_name, bucket_region)
        if f_enc:
            findings.append(f_enc)

    return findings
