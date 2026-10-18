"""
CloudGuard Stage 7: Offline Detection Accuracy & Ground Truth Validation Tool.

Validates the detection accuracy of CloudGuard scanners against confirmed ground-truth
security misconfigurations defined in tests/expected_findings.json without requiring
AWS credentials, active internet, or deployed cloud infrastructure.

Key Viva Concepts & Principles:
- True Positives (TP): Planted misconfigurations that CloudGuard accurately detected.
- False Positives (FP): Benign or compliant configurations falsely flagged as vulnerabilities.
- False Negatives (FN): Planted misconfigurations that CloudGuard failed to detect.
- Precision: TP / (TP + FP) - measures false-alarm resistance.
- Recall: TP / (TP + FN) - measures coverage completeness.
- Zero-Denominator Convention: 0.0% is reported when (TP + FP) or (TP + FN) is 0.
"""

from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import MagicMock
from botocore.exceptions import ClientError

# Ensure cloudguard package can be imported from workspace root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cloudguard.models import Finding
from cloudguard.cis_mapping import tag_findings_with_cis
from cloudguard.scanners.s3_scanner import scan_s3
from cloudguard.scanners.iam_scanner import scan_iam
from cloudguard.scanners.sg_scanner import scan_security_groups
from cloudguard.scanners.monitoring_scanner import scan_monitoring


@dataclass
class CategoryMetrics:
    category: str
    expected_count: int
    actual_count: int
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float


@dataclass
class ValidationReport:
    total_expected: int
    total_actual: int
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    category_metrics: Dict[str, CategoryMetrics]
    matched_pairs: List[Tuple[Dict[str, Any], Finding]]
    unmatched_actual: List[Finding]
    unmatched_expected: List[Dict[str, Any]]


def load_expected_findings(json_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """
    Loads ground truth misconfiguration entries from expected_findings.json.
    Resolves relative to this script file to ensure directory-independent execution.
    """
    if json_path is None:
        json_path = Path(__file__).resolve().parent / "expected_findings.json"

    with open(json_path, "r", encoding="utf-8") as f:
        return json.load(f)


def build_mock_clients() -> Dict[str, MagicMock]:
    """
    Constructs a fully synthetic, mocked AWS environment mirroring both the
    confirmed misconfigurations in tests/expected_findings.json and compliant
    baseline resources to test false positive resistance.
    """
    # -------------------------------------------------------------------------
    # 1. Mock S3 Client
    # -------------------------------------------------------------------------
    mock_s3 = MagicMock()
    mock_s3.list_buckets.return_value = {
        "Buckets": [
            {"Name": "cloudguard-test-pub-policy"},
            {"Name": "cloudguard-test-pub-acl"},
            {"Name": "cloudguard-test-no-encrypt"},
            {"Name": "cloudguard-test-compliant-bucket"},
        ]
    }
    mock_s3.get_bucket_location.return_value = {"LocationConstraint": "ap-south-1"}

    def s3_policy_status(Bucket: str) -> Dict[str, Any]:
        if Bucket == "cloudguard-test-pub-policy":
            return {"PolicyStatus": {"IsPublic": True}}
        raise ClientError(
            {"Error": {"Code": "NoSuchBucketPolicy", "Message": "The bucket policy does not exist"}},
            "GetBucketPolicyStatus"
        )
    mock_s3.get_bucket_policy_status.side_effect = s3_policy_status

    def s3_policy(Bucket: str) -> Dict[str, Any]:
        if Bucket == "cloudguard-test-pub-policy":
            return {
                "Policy": json.dumps({
                    "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}]
                })
            }
        raise ClientError(
            {"Error": {"Code": "NoSuchBucketPolicy", "Message": "The bucket policy does not exist"}},
            "GetBucketPolicy"
        )
    mock_s3.get_bucket_policy.side_effect = s3_policy

    def s3_bpa(Bucket: str) -> Dict[str, Any]:
        if Bucket == "cloudguard-test-pub-acl":
            return {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False,
                }
            }
        return {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }
    mock_s3.get_public_access_block.side_effect = s3_bpa

    mock_s3.get_bucket_acl.return_value = {
        "Grants": [{"Grantee": {"DisplayName": "owner"}, "Permission": "FULL_CONTROL"}]
    }

    def s3_enc(Bucket: str) -> Dict[str, Any]:
        if Bucket == "cloudguard-test-no-encrypt":
            raise ClientError(
                {"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError", "Message": "No SSE"}},
                "GetBucketEncryption"
            )
        return {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            }
        }
    mock_s3.get_bucket_encryption.side_effect = s3_enc

    # -------------------------------------------------------------------------
    # 2. Mock IAM Client
    # -------------------------------------------------------------------------
    mock_iam = MagicMock()
    mock_iam.list_users.return_value = {
        "Users": [
            {"UserName": "cloudguard-test-wildcard-admin-user"},
            {"UserName": "cloudguard-test-no-mfa-user"},
            {"UserName": "cloudguard-test-compliant-user"},
        ]
    }

    def iam_user_policies(UserName: str) -> Dict[str, Any]:
        if UserName == "cloudguard-test-wildcard-admin-user":
            return {"PolicyNames": ["WildcardAdminInline"]}
        return {"PolicyNames": []}
    mock_iam.list_user_policies.side_effect = iam_user_policies

    def iam_get_user_policy(UserName: str, PolicyName: str) -> Dict[str, Any]:
        if UserName == "cloudguard-test-wildcard-admin-user":
            return {
                "PolicyDocument": {
                    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
                }
            }
        return {"PolicyDocument": {}}
    mock_iam.get_user_policy.side_effect = iam_get_user_policy

    mock_iam.list_attached_user_policies.return_value = {"AttachedPolicies": []}

    def iam_mfa(UserName: str) -> Dict[str, Any]:
        if UserName in ("cloudguard-test-wildcard-admin-user", "cloudguard-test-compliant-user"):
            return {"MFADevices": [{"SerialNumber": f"arn:aws:iam::123456789012:mfa/{UserName}"}]}
        return {"MFADevices": []}
    mock_iam.list_mfa_devices.side_effect = iam_mfa

    def iam_login_profile(UserName: str) -> Dict[str, Any]:
        if UserName == "cloudguard-test-no-mfa-user":
            return {"LoginProfile": {"CreateDate": datetime.now(timezone.utc)}}
        raise ClientError(
            {"Error": {"Code": "NoSuchEntity", "Message": "No login profile"}},
            "GetLoginProfile",
        )
    mock_iam.get_login_profile.side_effect = iam_login_profile

    def iam_access_keys(UserName: str) -> Dict[str, Any]:
        if UserName == "cloudguard-test-no-mfa-user":
            return {
                "AccessKeyMetadata": [
                    {
                        "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                        "Status": "Active",
                        "CreateDate": datetime.now(timezone.utc) - timedelta(days=10),
                    }
                ]
            }
        return {"AccessKeyMetadata": []}
    mock_iam.list_access_keys.side_effect = iam_access_keys

    mock_iam.list_roles.return_value = {
        "Roles": [
            {"RoleName": "cloudguard-test-overprivileged-role", "Path": "/"},
            {"RoleName": "cloudguard-test-compliant-role", "Path": "/"},
            {"RoleName": "AWSServiceRoleForECS", "Path": "/aws-service-role/ecs/"},
        ]
    }

    def iam_role_attached(RoleName: str) -> Dict[str, Any]:
        if RoleName == "cloudguard-test-overprivileged-role":
            return {
                "AttachedPolicies": [
                    {
                        "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                        "PolicyName": "AdministratorAccess",
                    }
                ]
            }
        return {"AttachedPolicies": []}
    mock_iam.list_attached_role_policies.side_effect = iam_role_attached

    # -------------------------------------------------------------------------
    # 3. Mock EC2 Client (Security Groups)
    # -------------------------------------------------------------------------
    mock_ec2 = MagicMock()
    sg_list = [
        {
            "GroupId": "sg-open-ssh-1111",
            "GroupName": "cloudguard-test-open-ssh-sg",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                }
            ],
        },
        {
            "GroupId": "sg-open-rdp-2222",
            "GroupName": "cloudguard-test-open-rdp-sg",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 3389,
                    "ToPort": 3389,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                }
            ],
        },
        {
            "GroupId": "sg-open-db-3333",
            "GroupName": "cloudguard-test-open-db-sg",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 3306,
                    "ToPort": 3306,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 5432,
                    "ToPort": 5432,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                },
            ],
        },
        {
            "GroupId": "sg-compliant-4444",
            "GroupName": "cloudguard-test-compliant-web-sg",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 80,
                    "ToPort": 80,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "10.0.0.0/16"}],
                    "Ipv6Ranges": [],
                },
            ],
        },
    ]
    mock_ec2.describe_security_groups.return_value = {"SecurityGroups": sg_list}
    paginator = MagicMock()
    paginator.paginate.return_value = [{"SecurityGroups": sg_list}]
    mock_ec2.get_paginator.return_value = paginator

    # -------------------------------------------------------------------------
    # 4. Mock CloudTrail & CloudWatch Clients
    # -------------------------------------------------------------------------
    mock_cloudtrail = MagicMock()
    mock_cloudtrail.describe_trails.return_value = {
        "trailList": [
            {
                "Name": "cloudguard-test-insecure-trail",
                "TrailARN": "arn:aws:cloudtrail:ap-south-1:123456789012:trail/cloudguard-test-insecure-trail",
                "IsMultiRegionTrail": False,
                "LogFileValidationEnabled": False,
            },
            {
                "Name": "cloudguard-test-compliant-trail",
                "TrailARN": "arn:aws:cloudtrail:ap-south-1:123456789012:trail/cloudguard-test-compliant-trail",
                "IsMultiRegionTrail": True,
                "LogFileValidationEnabled": True,
            },
        ]
    }

    mock_cloudwatch = MagicMock()
    mock_cloudwatch.describe_alarms.return_value = {"MetricAlarms": []}

    return {
        "s3": mock_s3,
        "iam": mock_iam,
        "ec2": mock_ec2,
        "cloudtrail": mock_cloudtrail,
        "cloudwatch": mock_cloudwatch,
    }


def matches_finding(expected: Dict[str, Any], actual: Finding) -> bool:
    """
    Evaluates whether an actual finding matches an expected ground-truth item.

    Handles naming differences, CIS control mapping, resource pattern matching,
    and port specificity (e.g., distinguishing MySQL port 3306 vs PostgreSQL 5432
    on the same Security Group).
    """
    category = expected.get("category", "")
    res_pat = expected.get("resource_pattern", "")
    cis_id = expected.get("cis_id", "")
    exp_id = expected.get("id", "")

    # Category 1: S3
    if category == "S3":
        if actual.resource_type != "AWS::S3::Bucket":
            return False
        if res_pat not in actual.resource_id:
            return False
        if actual.cis_id != cis_id:
            return False
        if exp_id == "s3-public-policy":
            return "Public Access via Policy" in actual.check_name or actual.id.startswith("s3-public-policy")
        if exp_id == "s3-bpa-disabled":
            return "Block Public Access Disabled" in actual.check_name or actual.id.startswith("s3-bpa-disabled")
        if exp_id == "s3-missing-encryption":
            return "Missing Default Encryption" in actual.check_name or actual.id.startswith("s3-missing-encryption")
        return False

    # Category 2: IAM
    elif category == "IAM":
        if exp_id == "iam-overprivileged-role":
            if actual.resource_type != "AWS::IAM::Role":
                return False
            if res_pat not in actual.resource_id:
                return False
            return actual.cis_id == cis_id and (
                "Full Administrative Access" in actual.check_name or actual.id.startswith("iam-overprivileged-role")
            )
        else:
            if actual.resource_type != "AWS::IAM::User":
                return False
            if res_pat not in actual.resource_id:
                return False
            if exp_id == "iam-wildcard-policy":
                return actual.cis_id == cis_id and (
                    "Wildcard Administrative Privileges" in actual.check_name or "wildcard" in actual.id
                )
            if exp_id == "iam-user-no-mfa":
                return actual.cis_id == cis_id and (
                    "Without MFA Enabled" in actual.check_name or actual.id.startswith("iam-user-no-mfa")
                )
            if exp_id == "iam-active-access-key":
                return actual.cis_id == cis_id and (
                    "Active Access Key" in actual.check_name or actual.id.startswith("iam-active-access-key")
                )
            return False

    # Category 3: Security Groups
    elif category == "SECURITY_GROUP":
        if actual.resource_type != "AWS::EC2::SecurityGroup":
            return False
        group_name = actual.evidence.get("GroupName", "")
        if res_pat not in actual.resource_id and res_pat != group_name:
            return False
        if actual.cis_id != cis_id:
            return False

        exposed_port = actual.evidence.get("ExposedPort")

        # Specific port check matching (prevents false matches when CIS ID is identical)
        if exp_id == "sg-open-ssh":
            return exposed_port == 22 or "Port 22" in actual.check_name or actual.id.startswith("sg-open-22-")
        if exp_id == "sg-open-rdp":
            return exposed_port == 3389 or "Port 3389" in actual.check_name or actual.id.startswith("sg-open-3389-")
        if exp_id == "sg-open-mysql":
            return exposed_port == 3306 or "3306" in actual.check_name or actual.id.startswith("sg-open-3306-")
        if exp_id == "sg-open-postgres":
            return exposed_port == 5432 or "5432" in actual.check_name or actual.id.startswith("sg-open-5432-")
        return False

    # Category 4: Observability & Monitoring
    elif category == "MONITORING":
        if exp_id == "cloudwatch-missing-alarms":
            if actual.resource_type != "AWS::CloudWatch::Alarm":
                return False
            return actual.cis_id == cis_id and (
                actual.id == "cloudwatch-missing-alarms" or "Missing CloudWatch Metric Alarms" in actual.check_name
            )
        else:
            if actual.resource_type != "AWS::CloudTrail::Trail":
                return False
            if res_pat not in actual.resource_id:
                return False
            if exp_id == "cloudtrail-single-region":
                return actual.cis_id == cis_id and (
                    "Not Enabled In All Regions" in actual.check_name or actual.id.startswith("cloudtrail-single-region")
                )
            if exp_id == "cloudtrail-validation-disabled":
                return actual.cis_id == cis_id and (
                    "Log File Validation Disabled" in actual.check_name or actual.id.startswith("cloudtrail-validation-disabled")
                )
            return False

    return False


def get_finding_category(finding: Finding) -> str:
    """Derives reporting category from resource type."""
    if finding.resource_type == "AWS::S3::Bucket":
        return "S3"
    elif finding.resource_type in ("AWS::IAM::User", "AWS::IAM::Role"):
        return "IAM"
    elif finding.resource_type == "AWS::EC2::SecurityGroup":
        return "SECURITY_GROUP"
    elif finding.resource_type in ("AWS::CloudTrail::Trail", "AWS::CloudWatch::Alarm"):
        return "MONITORING"
    return "UNKNOWN"


def evaluate_validation(
    expected_findings: List[Dict[str, Any]],
    actual_findings: List[Finding],
) -> ValidationReport:
    """
    Performs 1-to-1 matching between ground-truth items and actual findings.
    A matched actual finding counts as a True Positive only once.
    Calculates overall and per-category TP, FP, FN, Precision, and Recall.
    """
    unmatched_expected = list(expected_findings)
    matched_pairs: List[Tuple[Dict[str, Any], Finding]] = []
    unmatched_actual: List[Finding] = []

    for actual in actual_findings:
        match_idx: Optional[int] = None
        for i, exp in enumerate(unmatched_expected):
            if matches_finding(exp, actual):
                match_idx = i
                break
        if match_idx is not None:
            matched_pairs.append((unmatched_expected.pop(match_idx), actual))
        else:
            unmatched_actual.append(actual)

    tp = len(matched_pairs)
    fp = len(unmatched_actual)
    fn = len(unmatched_expected)

    # Calculate metrics with zero-denominator convention (0.0% if denominator is zero)
    precision = round((tp / (tp + fp) * 100.0), 1) if (tp + fp) > 0 else 0.0
    recall = round((tp / (tp + fn) * 100.0), 1) if (tp + fn) > 0 else 0.0

    # Per-category breakdown
    categories = ["S3", "IAM", "SECURITY_GROUP", "MONITORING"]
    category_metrics: Dict[str, CategoryMetrics] = {}

    for cat in categories:
        cat_expected = [e for e in expected_findings if e.get("category") == cat]
        cat_tp = sum(1 for exp, _ in matched_pairs if exp.get("category") == cat)
        cat_fp = sum(1 for act in unmatched_actual if get_finding_category(act) == cat)
        cat_fn = sum(1 for exp in unmatched_expected if exp.get("category") == cat)
        cat_actual = cat_tp + cat_fp

        cat_prec = round((cat_tp / (cat_tp + cat_fp) * 100.0), 1) if (cat_tp + cat_fp) > 0 else 0.0
        cat_rec = round((cat_tp / (cat_tp + cat_fn) * 100.0), 1) if (cat_tp + cat_fn) > 0 else 0.0

        category_metrics[cat] = CategoryMetrics(
            category=cat,
            expected_count=len(cat_expected),
            actual_count=cat_actual,
            true_positives=cat_tp,
            false_positives=cat_fp,
            false_negatives=cat_fn,
            precision=cat_prec,
            recall=cat_rec,
        )

    return ValidationReport(
        total_expected=len(expected_findings),
        total_actual=len(actual_findings),
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        precision=precision,
        recall=recall,
        category_metrics=category_metrics,
        matched_pairs=matched_pairs,
        unmatched_actual=unmatched_actual,
        unmatched_expected=unmatched_expected,
    )


def format_validation_summary(report: ValidationReport, source_path: Path) -> str:
    """Formats ASCII terminal summary of validation results."""
    lines = [
        "=" * 74,
        " CloudGuard - Offline Detection Accuracy & Ground Truth Validation",
        " (Synthetic Mock Environment - No live AWS calls or credentials used)",
        "=" * 74,
        f" Ground Truth Source : {source_path}",
        f" Total Expected Items: {report.total_expected}",
        f" Total Scanned Items : {report.total_actual}",
        "-" * 74,
        " OVERALL DETECTION METRICS",
        "-" * 74,
        f" True Positives  (TP) : {report.true_positives}",
        f" False Positives (FP) : {report.false_positives}",
        f" False Negatives (FN) : {report.false_negatives}",
        f" Precision            : {report.precision:.1f}%",
        f" Recall               : {report.recall:.1f}%",
        "",
        " Note: Convention defines 0.0% when the denominator (TP+FP or TP+FN)",
        " is zero to represent an undefined rate without division by zero.",
        "-" * 74,
        " PER-CATEGORY BREAKDOWN",
        "-" * 74,
        f" {'Category':<16} {'Expected':>8} {'Actual':>8} {'TP':>5} {'FP':>5} {'FN':>5} {'Precision':>10} {'Recall':>8}",
        f" {'-'*16:<16} {'-'*8:>8} {'-'*8:>8} {'-'*5:>5} {'-'*5:>5} {'-'*5:>5} {'-'*10:>10} {'-'*8:>8}",
    ]

    for cat_name, m in report.category_metrics.items():
        lines.append(
            f" {cat_name:<16} {m.expected_count:>8} {m.actual_count:>8} {m.true_positives:>5} "
            f"{m.false_positives:>5} {m.false_negatives:>5} {m.precision:>9.1f}% {m.recall:>7.1f}%"
        )

    lines.append("=" * 74)
    return "\n".join(lines)


def run_offline_validation(
    expected_path: Optional[Path] = None,
    region: str = "ap-south-1",
) -> Tuple[ValidationReport, str]:
    """
    Executes the offline validation pipeline:
    1. Loads expected findings from JSON.
    2. Runs all 4 real scanners using synthetic mock clients.
    3. Tags findings with CIS controls.
    4. Evaluates precision and recall.
    5. Returns the structured report and formatted summary string.
    """
    if expected_path is None:
        expected_path = Path(__file__).resolve().parent / "expected_findings.json"

    expected_findings = load_expected_findings(expected_path)
    mock_clients = build_mock_clients()

    all_findings: List[Finding] = []
    all_findings.extend(scan_s3(client=mock_clients["s3"], region_name=region))
    all_findings.extend(scan_iam(client=mock_clients["iam"]))
    all_findings.extend(scan_security_groups(client=mock_clients["ec2"], region_name=region))
    all_findings.extend(
        scan_monitoring(
            cloudtrail_client=mock_clients["cloudtrail"],
            cloudwatch_client=mock_clients["cloudwatch"],
            region_name=region,
        )
    )

    # Tag findings with official CIS control IDs
    tagged_findings = tag_findings_with_cis(all_findings)

    # INFO findings describe unverified state and are not misconfiguration detections.
    confirmed_findings = [finding for finding in tagged_findings if finding.severity != "INFO"]
    report = evaluate_validation(expected_findings, confirmed_findings)
    summary_text = format_validation_summary(report, expected_path)

    return report, summary_text


def main() -> int:
    """CLI entrypoint for standalone execution: python tests/validate.py"""
    report, summary_text = run_offline_validation()
    print(summary_text)

    # Exit code 0 if 100% precision and 100% recall, else 1
    if report.precision == 100.0 and report.recall == 100.0:
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
