"""
Unit Tests for Stage 3: S3 and IAM Scanners.

Why this file is essential:
Enables full verification of scanning logic, edge cases, and finding generation
WITHOUT requiring active AWS credentials or deployed cloud infrastructure.
Matches the deliberate misconfigurations planted in the Terraform testbed.
"""

import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock
import pytest
from botocore.exceptions import ClientError

# Ensure project root is available in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cloudguard.scanners.s3_scanner import scan_s3
from cloudguard.scanners.iam_scanner import scan_iam


# =============================================================================
# S3 Scanner Tests
# =============================================================================

def test_s3_scanner_detects_public_policy():
    """Verify detection of S3 bucket with public policy."""
    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {
        "Buckets": [{"Name": "cloudguard-test-pub-policy"}]
    }
    mock_s3.get_bucket_location.return_value = {"LocationConstraint": "ap-south-1"}
    mock_s3.get_bucket_policy_status.return_value = {
        "PolicyStatus": {"IsPublic": True}
    }
    mock_s3.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
    }
    mock_s3.get_bucket_acl.return_value = {"Grants": []}
    mock_s3.get_bucket_encryption.return_value = {
        "ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}
    }

    findings = scan_s3(client=mock_s3, region_name="ap-south-1")
    assert len(findings) == 1
    f = findings[0]
    assert f.check_name == "S3 Bucket Public Access via Policy"
    assert f.severity == "CRITICAL"
    assert f.exposure == "PUBLIC"
    assert f.resource_id == "cloudguard-test-pub-policy"


def test_s3_scanner_detects_bpa_disabled_and_public_acl():
    """Verify detection of S3 bucket with disabled Block Public Access and public ACL."""
    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {
        "Buckets": [{"Name": "cloudguard-test-pub-acl"}]
    }
    mock_s3.get_bucket_location.return_value = {"LocationConstraint": "ap-south-1"}
    # No public policy
    mock_s3.get_bucket_policy_status.side_effect = ClientError(
        {"Error": {"Code": "NoSuchBucketPolicy", "Message": "The bucket policy does not exist"}},
        "GetBucketPolicyStatus"
    )
    mock_s3.get_bucket_policy.side_effect = ClientError(
        {"Error": {"Code": "NoSuchBucketPolicy", "Message": "The bucket policy does not exist"}},
        "GetBucketPolicy"
    )
    # BPA disabled
    mock_s3.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        }
    }
    # Public ACL
    mock_s3.get_bucket_acl.return_value = {
        "Grants": [
            {
                "Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
                "Permission": "READ"
            }
        ]
    }
    mock_s3.get_bucket_encryption.return_value = {
        "ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}
    }

    findings = scan_s3(client=mock_s3, region_name="ap-south-1")
    check_names = [f.check_name for f in findings]
    assert "S3 Bucket Block Public Access Disabled" in check_names
    assert "S3 Bucket Public Access via ACL" in check_names


def test_s3_scanner_marks_missing_explicit_encryption_as_unverified():
    """Missing explicit defaults do not prove existing objects are unencrypted."""
    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {
        "Buckets": [{"Name": "cloudguard-test-no-encrypt"}]
    }
    mock_s3.get_bucket_location.return_value = {"LocationConstraint": "ap-south-1"}
    mock_s3.get_bucket_policy_status.side_effect = ClientError(
        {"Error": {"Code": "NoSuchBucketPolicy", "Message": "None"}}, "GetBucketPolicyStatus"
    )
    mock_s3.get_bucket_policy.side_effect = ClientError(
        {"Error": {"Code": "NoSuchBucketPolicy", "Message": "None"}}, "GetBucketPolicy"
    )
    mock_s3.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
    }
    mock_s3.get_bucket_acl.return_value = {"Grants": []}
    mock_s3.get_bucket_encryption.side_effect = ClientError(
        {"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError", "Message": "None"}},
        "GetBucketEncryption"
    )

    findings = scan_s3(client=mock_s3, region_name="ap-south-1")
    assert len(findings) == 1
    assert findings[0].check_name == "S3 Explicit Default Encryption Configuration Unverified"
    assert findings[0].severity == "INFO"
    assert findings[0].cis_id == "N/A"


def test_s3_scanner_compliant_baseline_produces_zero_findings():
    """Verify that a compliant, fully secured bucket produces 0 findings (no false positives)."""
    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {
        "Buckets": [{"Name": "cloudguard-test-secure-baseline"}]
    }
    mock_s3.get_bucket_location.return_value = {"LocationConstraint": "ap-south-1"}
    mock_s3.get_bucket_policy_status.side_effect = ClientError(
        {"Error": {"Code": "NoSuchBucketPolicy", "Message": "None"}}, "GetBucketPolicyStatus"
    )
    mock_s3.get_bucket_policy.side_effect = ClientError(
        {"Error": {"Code": "NoSuchBucketPolicy", "Message": "None"}}, "GetBucketPolicy"
    )
    mock_s3.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
    }
    mock_s3.get_bucket_acl.return_value = {"Grants": []}
    mock_s3.get_bucket_encryption.return_value = {
        "ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}
    }

    findings = scan_s3(client=mock_s3, region_name="ap-south-1")
    assert len(findings) == 0, "Compliant baseline bucket must produce ZERO false positive findings!"


# =============================================================================
# IAM Scanner Tests
# =============================================================================

def test_iam_scanner_detects_wildcard_policy():
    """Verify detection of IAM user with Action:* and Resource:* policy."""
    mock_iam = MagicMock()
    mock_iam.list_users.return_value = {
        "Users": [{"UserName": "cloudguard-test-wildcard-admin-user"}]
    }
    mock_iam.list_user_policies.return_value = {"PolicyNames": ["InsecureAdminPolicy"]}
    mock_iam.get_user_policy.return_value = {
        "PolicyDocument": {
            "Statement": [
                {"Effect": "Allow", "Action": "*", "Resource": "*"}
            ]
        }
    }
    mock_iam.list_attached_user_policies.return_value = {"AttachedPolicies": []}
    mock_iam.list_mfa_devices.return_value = {"MFADevices": [{"SerialNumber": "arn:aws:iam::123:mfa/user"}]}
    mock_iam.list_access_keys.return_value = {"AccessKeyMetadata": []}
    mock_iam.list_roles.return_value = {"Roles": []}

    findings = scan_iam(client=mock_iam)
    assert len(findings) == 1
    f = findings[0]
    assert f.check_name == "IAM Policy Grants Wildcard Administrative Privileges (*:*)"
    assert f.severity == "CRITICAL"
    assert f.resource_id == "cloudguard-test-wildcard-admin-user"


def test_iam_scanner_detects_missing_mfa_but_not_compliant_active_key():
    """A key within the 90-day window is not a rotation finding."""
    mock_iam = MagicMock()
    mock_iam.list_users.return_value = {
        "Users": [{"UserName": "cloudguard-test-no-mfa-user"}]
    }
    mock_iam.list_user_policies.return_value = {"PolicyNames": []}
    mock_iam.list_attached_user_policies.return_value = {"AttachedPolicies": []}
    mock_iam.list_mfa_devices.return_value = {"MFADevices": []}  # No MFA!
    mock_iam.get_login_profile.return_value = {"LoginProfile": {"CreateDate": datetime.now(timezone.utc)}}
    mock_iam.list_access_keys.return_value = {
        "AccessKeyMetadata": [
            {
                "AccessKeyId": "AKIAEXAMPLE12345678",
                "Status": "Active",
                "CreateDate": datetime.now(timezone.utc) - timedelta(days=10)
            }
        ]
    }
    mock_iam.list_roles.return_value = {"Roles": []}

    findings = scan_iam(client=mock_iam)
    check_names = [f.check_name for f in findings]
    assert "IAM User Without MFA Enabled" in check_names
    assert not any("Active Access Key" in name for name in check_names)


@pytest.mark.parametrize(
    "elapsed, overdue",
    [
        (timedelta(0), False),
        (timedelta(days=90), False),
        (timedelta(days=90, seconds=1), True),
        (timedelta(days=91), True),
        (-timedelta(days=1), False),
    ],
)
def test_access_key_rotation_boundary(elapsed, overdue):
    """The exact 90-day limit is compliant; any older active key is overdue."""
    from cloudguard.scanners.iam_scanner import check_user_access_keys

    mock_iam = MagicMock()
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    mock_iam.list_access_keys.return_value = {
        "AccessKeyMetadata": [{
            "AccessKeyId": "AKIAEXAMPLE12345678",
            "Status": "Active",
            "CreateDate": now - elapsed,
        }]
    }

    findings = check_user_access_keys(mock_iam, "alice", now=now)
    assert bool(findings) is overdue
    mock_iam.update_access_key.assert_not_called()
    mock_iam.create_access_key.assert_not_called()
    mock_iam.delete_access_key.assert_not_called()
    if overdue:
        assert findings[0].evidence["AgeDays"] > 90
        assert findings[0].evidence["IsOverdueForRotation"] is True


def test_access_key_without_creation_date_is_not_assumed_compliant():
    from cloudguard.scanners.iam_scanner import check_user_access_keys

    mock_iam = MagicMock()
    mock_iam.list_access_keys.return_value = {"AccessKeyMetadata": [{
        "AccessKeyId": "AKIAEXAMPLE12345678", "Status": "Active",
    }]}
    with pytest.raises(RuntimeError, match="CreateDate is missing or invalid"):
        check_user_access_keys(mock_iam, "alice")


def test_iam_scanner_detects_overprivileged_role():
    """Verify detection of role with AdministratorAccess managed policy."""
    mock_iam = MagicMock()
    mock_iam.list_users.return_value = {"Users": []}
    mock_iam.list_roles.return_value = {
        "Roles": [
            {
                "RoleName": "cloudguard-test-overprivileged-role",
                "Path": "/cloudguard-test/"
            }
        ]
    }
    mock_iam.list_attached_role_policies.return_value = {
        "AttachedPolicies": [
            {
                "PolicyName": "AdministratorAccess",
                "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
            }
        ]
    }

    findings = scan_iam(client=mock_iam)
    assert len(findings) == 1
    f = findings[0]
    assert f.check_name == "IAM Role Has Full Administrative Access"
    assert f.severity == "CRITICAL"
    assert f.resource_id == "cloudguard-test-overprivileged-role"


def test_iam_scanner_compliant_baseline_produces_zero_findings():
    """Verify that a scoped least-privilege role produces 0 findings (no false positives)."""
    mock_iam = MagicMock()
    mock_iam.list_users.return_value = {"Users": []}
    mock_iam.list_roles.return_value = {
        "Roles": [
            {
                "RoleName": "cloudguard-test-compliant-scoped-role",
                "Path": "/cloudguard-test/"
            }
        ]
    }
    mock_iam.list_attached_role_policies.return_value = {
        "AttachedPolicies": [
            {
                "PolicyName": "ScopedReadOnly",
                "PolicyArn": "arn:aws:iam::123456789012:policy/ScopedReadOnly"
            }
        ]
    }
    mock_iam.get_policy.return_value = {"Policy": {"DefaultVersionId": "v1"}}
    mock_iam.get_policy_version.return_value = {
        "PolicyVersion": {
            "Document": {
                "Statement": [
                    {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::example/*"}
                ]
            }
        }
    }

    findings = scan_iam(client=mock_iam)
    assert len(findings) == 0, "Compliant least-privilege role must produce ZERO false positive findings!"


def test_s3_scanner_raises_on_list_buckets_client_error():
    """Verify that s3_scanner raises ClientError when list_buckets fails (e.g. AccessDenied)."""
    mock_s3 = MagicMock()
    mock_s3.list_buckets.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}},
        "ListBuckets"
    )
    with pytest.raises(ClientError):
        scan_s3(client=mock_s3)


def test_iam_scanner_raises_on_list_users_client_error():
    """Verify that iam_scanner raises ClientError when list_users fails (e.g. AccessDenied)."""
    mock_iam = MagicMock()
    mock_iam.list_users.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}},
        "ListUsers"
    )
    with pytest.raises(ClientError):
        scan_iam(client=mock_iam)

