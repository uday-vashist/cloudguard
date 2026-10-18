from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from cloudguard.aws_session import ReadOnlyClientWrapper, ReadOnlyViolationError
from cloudguard.cis_mapping import get_cis_id_for_check, tag_findings_with_cis
from cloudguard.models import Finding
from cloudguard.report import generate_html_report
from cloudguard.scanners.iam_scanner import check_user_mfa, scan_iam
from cloudguard.scanners.monitoring_scanner import check_cloudtrail_trails, check_cloudwatch_alarms
from cloudguard.scanners.s3_scanner import check_bucket_acl, scan_s3
from cloudguard.scanners.sg_scanner import scan_security_groups
from cloudguard.scoring import aggregate_risk_score, calculate_risk_score, score_and_rank_findings


def _client_error(code: str, operation: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "mock failure"}}, operation)


def test_mfa_requires_confirmed_console_profile_and_surfaces_api_errors():
    iam = MagicMock()
    iam.list_mfa_devices.return_value = {"MFADevices": []}
    iam.get_login_profile.side_effect = _client_error("NoSuchEntity", "GetLoginProfile")
    assert check_user_mfa(iam, "api-only-user") is None

    iam.get_login_profile.side_effect = _client_error("AccessDenied", "GetLoginProfile")
    with pytest.raises(ClientError):
        check_user_mfa(iam, "unknown-console-user")

    iam.list_mfa_devices.side_effect = _client_error("AccessDenied", "ListMFADevices")
    with pytest.raises(ClientError):
        check_user_mfa(iam, "unreadable-user")


def test_iam_user_pagination_reads_later_pages():
    iam = MagicMock()
    iam.list_users.side_effect = [
        {"Users": [{"UserName": "first"}], "IsTruncated": True, "Marker": "page-2"},
        {"Users": [{"UserName": "second"}], "IsTruncated": False},
    ]
    iam.list_mfa_devices.return_value = {"MFADevices": [{"SerialNumber": "mfa"}]}
    iam.list_user_policies.return_value = {"PolicyNames": []}
    iam.list_attached_user_policies.return_value = {"AttachedPolicies": []}
    iam.list_access_keys.return_value = {"AccessKeyMetadata": []}
    iam.list_roles.return_value = {"Roles": []}

    scan_iam(iam)

    assert iam.list_users.call_count == 2
    assert iam.list_users.call_args_list[1].kwargs["Marker"] == "page-2"
    assert iam.list_mfa_devices.call_count == 2


def test_cloudtrail_pagination_and_multi_region_coverage():
    cloudtrail = MagicMock()
    cloudtrail.describe_trails.side_effect = [
        {"trailList": [{"Name": "regional", "IsMultiRegionTrail": False}], "NextToken": "page-2"},
        {"trailList": [{"Name": "global", "IsMultiRegionTrail": True, "LogFileValidationEnabled": True}]},
    ]

    findings = check_cloudtrail_trails(cloudtrail, "ap-south-1")

    assert cloudtrail.describe_trails.call_count == 2
    assert not any(f.check_name == "CloudTrail Not Enabled In All Regions" for f in findings)


def test_empty_cloudtrail_response_and_cloudwatch_api_failure_are_distinct():
    cloudtrail = MagicMock()
    cloudtrail.describe_trails.return_value = {"trailList": []}
    observation = check_cloudtrail_trails(cloudtrail, "ap-south-1")[0]
    assert observation.severity == "INFO"
    assert "does not establish account-wide absence" in observation.evidence["Status"]

    cloudwatch = MagicMock()
    cloudwatch.describe_alarms.side_effect = _client_error("AccessDenied", "DescribeAlarms")
    with pytest.raises(ClientError):
        check_cloudwatch_alarms(cloudwatch, "ap-south-1")


def test_cloudwatch_alarm_pagination_does_not_claim_verified_configuration():
    cloudwatch = MagicMock()
    cloudwatch.describe_alarms.side_effect = [
        {"MetricAlarms": [{"AlarmName": "routine-alarm"}], "NextToken": "page-2"},
        {"MetricAlarms": [{"AlarmName": "RootAccountUsageAlarm", "MetricName": "RootUsage"}]},
    ]

    findings = check_cloudwatch_alarms(cloudwatch, "eu-west-1")

    assert cloudwatch.describe_alarms.call_count == 2
    assert len(findings) == 1
    assert findings[0].severity == "INFO"
    assert findings[0].region == "eu-west-1"
    assert "Configuration Unverified" in findings[0].check_name


def test_cloudwatch_unmatched_existing_alarms_are_not_called_missing():
    cloudwatch = MagicMock()
    cloudwatch.describe_alarms.return_value = {"MetricAlarms": [{"AlarmName": "application-latency"}]}

    findings = check_cloudwatch_alarms(cloudwatch, "us-east-1")

    assert len(findings) == 1
    assert findings[0].severity == "INFO"
    assert "Status Unverified" in findings[0].check_name


def test_s3_pagination_and_permission_failures():
    s3 = MagicMock()
    s3.list_buckets.side_effect = [
        {"Buckets": [{"Name": "first"}], "NextToken": "page-2"},
        {"Buckets": [{"Name": "second"}]},
    ]
    s3.get_bucket_location.return_value = {"LocationConstraint": "us-east-1"}
    s3.get_bucket_policy_status.return_value = {"PolicyStatus": {"IsPublic": False}}
    s3.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": {
        "BlockPublicAcls": True, "IgnorePublicAcls": True,
        "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
    }}
    s3.get_bucket_acl.return_value = {"Grants": []}
    s3.get_bucket_encryption.return_value = {"ServerSideEncryptionConfiguration": {
        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}],
    }}

    assert scan_s3(s3) == []
    assert s3.list_buckets.call_count == 2
    assert s3.get_bucket_location.call_count == 2

    s3.get_bucket_acl.side_effect = _client_error("AccessDenied", "GetBucketAcl")
    with pytest.raises(ClientError):
        check_bucket_acl(s3, "first", "us-east-1")


def test_s3_acl_disabled_by_object_ownership_is_not_a_scan_failure():
    s3 = MagicMock()
    s3.get_bucket_acl.side_effect = _client_error("AccessControlListNotSupported", "GetBucketAcl")
    assert check_bucket_acl(s3, "owner-enforced", "us-east-1") is None


def test_security_group_pagination_ipv6_and_non_sensitive_ports():
    ec2 = MagicMock()
    ec2.describe_security_groups.side_effect = [
        {"SecurityGroups": [{"GroupId": "sg-1", "IpPermissions": [{
            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
            "Ipv6Ranges": [{"CidrIpv6": "0:0:0:0:0:0:0:0/0"}],
        }]}], "NextToken": "page-2"},
        {"SecurityGroups": [{"GroupId": "sg-2", "IpPermissions": [{
            "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }]}]},
    ]

    findings = scan_security_groups(ec2, "us-east-2")

    assert ec2.describe_security_groups.call_count == 2
    assert len(findings) == 1
    assert findings[0].resource_id == "sg-1"
    assert findings[0].evidence["PublicCidrs"] == ["0:0:0:0:0:0:0:0/0"]


def test_info_scoring_aggregate_and_cis_mapping():
    confirmed = Finding(
        id="risk", check_name="Confirmed issue", resource_type="AWS::IAM::User",
        resource_id="u1", region="global", severity="HIGH", exposure="INTERNAL",
        sensitivity="MEDIUM", evidence={},
    )
    observation = Finding(
        id="info", check_name="Status unverified", resource_type="AWS::CloudTrail::Trail",
        resource_id="t1", region="us-east-1", severity="INFO", exposure="INTERNAL",
        sensitivity="LOW", evidence={},
    )
    ranked = score_and_rank_findings([observation, confirmed])

    assert [finding.risk_score for finding in ranked] == [10.5, 0.0]
    assert aggregate_risk_score(ranked) == 10.5
    assert calculate_risk_score("INFO", "INTERNAL", "LOW") == 0.0
    assert get_cis_id_for_check(observation.check_name) == "N/A"
    tag_findings_with_cis([observation])
    assert observation.cis_id == "N/A"
    with pytest.raises(ValueError):
        calculate_risk_score("UNKNOWN", "INTERNAL", "LOW")


def test_report_redacts_sensitive_evidence(tmp_path):
    finding = Finding(
        id="secret-evidence", check_name="Evidence redaction", resource_type="AWS::IAM::User",
        resource_id="user", region="global", severity="INFO", exposure="INTERNAL",
        sensitivity="LOW", evidence={
            "SecretAccessKey": "do-not-print-this",
            "nested": [{"session_token": "also-secret"}],
            "AccessKeyId": "AKIAEXAMPLE",
        },
    )
    path = tmp_path / "redacted.html"

    generate_html_report([finding], output_path=str(path))
    html = path.read_text(encoding="utf-8")

    assert "do-not-print-this" not in html
    assert "also-secret" not in html
    assert html.count("[REDACTED]") == 2
    assert "AKIAEXAMPLE" in html


def test_read_only_wrapper_blocks_writes_and_hides_raw_client():
    raw = MagicMock()
    raw.list_buckets.return_value = {"Buckets": []}
    wrapped = ReadOnlyClientWrapper(raw, "s3")

    assert wrapped.list_buckets() == {"Buckets": []}
    mutations = (
        "create_bucket",
        "put_bucket_policy",
        "update_bucket",
        "modify_bucket",
        "enable_bucket_encryption",
        "disable_bucket_encryption",
        "delete_bucket",
    )
    for operation in mutations:
        with pytest.raises(ReadOnlyViolationError):
            getattr(wrapped, operation)()
        getattr(raw, operation).assert_not_called()
    with pytest.raises(ReadOnlyViolationError):
        wrapped.get_paginator("DeleteObjects")
    with pytest.raises(AttributeError):
        _ = wrapped._raw_client
    with pytest.raises(AttributeError):
        _ = wrapped.__dict__


def test_read_only_wrapper_allows_attached_policy_listing_but_blocks_mutations():
    raw = MagicMock()
    raw.list_attached_user_policies.return_value = {"AttachedPolicies": []}
    wrapped = ReadOnlyClientWrapper(raw, "iam")

    assert wrapped.list_attached_user_policies(UserName="alice") == {"AttachedPolicies": []}
    raw.list_attached_user_policies.assert_called_once_with(UserName="alice")

    for operation in ("attach_user_policy", "detach_user_policy"):
        with pytest.raises(ReadOnlyViolationError):
            getattr(wrapped, operation)(UserName="alice", PolicyArn="arn:example")
        getattr(raw, operation).assert_not_called()