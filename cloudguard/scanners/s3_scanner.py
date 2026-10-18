"""
CloudGuard S3 Storage Security Scanner.

Audits Amazon S3 storage resources against security misconfigurations:
1. Public Bucket Policy (Policy granting public access to Principal "*")
2. Incomplete Block Public Access (BPA) settings
3. Public Bucket ACLs (Grants to AllUsers or AuthenticatedUsers)
4. Explicit default encryption status (informational; existing objects are not inspected)

VIVA CONCEPTS:
- Principle: S3 buckets must be private by default. Data leaks often occur due to
  misconfigured bucket policies, legacy ACLs, or disabled Block Public Access.
- Read-Only Compliance: Only calls list_buckets, get_bucket_policy_status,
  get_bucket_policy, get_public_access_block, get_bucket_acl, get_bucket_encryption,
  and get_bucket_location.
"""

import json
from typing import Any, List, Optional
from botocore.exceptions import ClientError
from cloudguard.aws_session import get_client
from cloudguard.models import Finding
from cloudguard.scanners._utils import collect_pages

# Well-known public grantee URIs in AWS S3 ACLs
PUBLIC_ALL_USERS_URI = "http://acs.amazonaws.com/groups/global/AllUsers"
PUBLIC_AUTH_USERS_URI = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"


def _has_public_principal(principal: Any) -> bool:
    if principal == "*":
        return True
    if not isinstance(principal, dict):
        return False
    return any(
        value == "*" or (isinstance(value, list) and "*" in value)
        for value in principal.values()
    )


def check_bucket_policy(s3_client: Any, bucket_name: str, region: str) -> Optional[Finding]:
    """
    Check if the bucket policy grants public access.
    Uses s3.get_bucket_policy_status and falls back to inspecting policy statements.
    """
    # 1. Try get_bucket_policy_status (boto3 official helper)
    try:
        status_resp = s3_client.get_bucket_policy_status(Bucket=bucket_name)
        policy_status = status_resp.get("PolicyStatus", {})
        if policy_status.get("IsPublic") is True:
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
        if "IsPublic" in policy_status:
            return None
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code != "NoSuchBucketPolicy":
            raise
        return None

    # 2. Inspect raw bucket policy if available
    try:
        policy_resp = s3_client.get_bucket_policy(Bucket=bucket_name)
        raw_policy = policy_resp.get("Policy", "{}")
        policy_doc = json.loads(raw_policy) if isinstance(raw_policy, str) else raw_policy

        statements = policy_doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        for stmt in statements:
            if stmt.get("Effect") == "Allow":
                principal = stmt.get("Principal")
                if _has_public_principal(principal):
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
        if error_code != "NoSuchBucketPolicy":
            raise

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

        disabled_settings = [
            key for key in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
            if config.get(key) is not True
        ]

        if disabled_settings or not config:
            return Finding(
                id=f"s3-bpa-disabled-{bucket_name}",
                check_name="S3 Bucket Block Public Access Disabled",
                resource_type="AWS::S3::Bucket",
                resource_id=bucket_name,
                region=region,
                severity="HIGH",
                exposure="INTERNAL",
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
        if error_code == "NoSuchPublicAccessBlockConfiguration":
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
        raise
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
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") != "AccessControlListNotSupported":
            raise
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
                check_name="S3 Explicit Default Encryption Configuration Unverified",
                resource_type="AWS::S3::Bucket",
                resource_id=bucket_name,
                region=region,
                severity="INFO",
                exposure="INTERNAL",
                sensitivity="LOW",
                evidence={
                    "ServerSideEncryptionConfiguration": enc_resp,
                    "Status": "No explicit default rule was returned; existing object encryption was not inspected.",
                },
                remediation="Verify encryption of existing objects with an approved inventory or data-classification process; configure an explicit bucket default only if required by policy.",
            )
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code == "ServerSideEncryptionConfigurationNotFoundError":
            return Finding(
                id=f"s3-missing-encryption-{bucket_name}",
                check_name="S3 Explicit Default Encryption Configuration Unverified",
                resource_type="AWS::S3::Bucket",
                resource_id=bucket_name,
                region=region,
                severity="INFO",
                exposure="INTERNAL",
                sensitivity="LOW",
                evidence={
                    "Error": "No explicit ServerSideEncryptionConfiguration found",
                    "Status": "Existing object encryption was not inspected.",
                },
                remediation="Verify encryption of existing objects with an approved inventory or data-classification process; configure an explicit bucket default only if required by policy.",
            )
        raise
    return None


def scan_s3(client: Optional[Any] = None, region_name: str = "ap-south-1") -> List[Finding]:
    """
    Main S3 scanner entry point.
    Audits all S3 buckets accessible by the credentials.
    """
    s3_client = client or get_client("s3", region_name=region_name)
    findings: List[Finding] = []

    try:
        buckets = collect_pages(s3_client, "list_buckets", "Buckets")
    except ClientError:
        raise

    for b in buckets:
        bucket_name = b.get("Name", "")
        if not bucket_name:
            continue

        # Determine bucket region (defaults to us-east-1 if None)
        try:
            loc_resp = s3_client.get_bucket_location(Bucket=bucket_name)
            loc = loc_resp.get("LocationConstraint")
            bucket_region = "eu-west-1" if loc == "EU" else (loc or "us-east-1")
        except ClientError:
            raise

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
