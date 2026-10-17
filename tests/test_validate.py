"""
Unit tests for CloudGuard Stage 7: Offline Detection-Validation Tool (tests/validate.py).

Verifies:
1. Ground-truth loading from expected_findings.json.
2. Perfect matching (TP=14, FP=0, FN=0, 100% precision, 100% recall).
3. Missing expected findings (FN tracking and reduced recall).
4. Unexpected actual findings (FP tracking and reduced precision).
5. Duplicate matching prevention (preventing double-counting of TPs).
6. Zero-denominator metrics (handling 0.0% without ZeroDivisionError).
7. Security group port specificity (preventing false matches on identical CIS IDs).
8. Offline execution without AWS credentials or network access.
"""

import os
from pathlib import Path
import pytest
from unittest.mock import patch

from cloudguard.models import Finding
from tests.validate import (
    load_expected_findings,
    build_mock_clients,
    matches_finding,
    evaluate_validation,
    run_offline_validation,
    main,
    ValidationReport,
)


def test_ground_truth_loading():
    """Verify load_expected_findings loads all 14 testbed ground truth definitions."""
    findings = load_expected_findings()
    assert isinstance(findings, list)
    assert len(findings) == 14

    required_keys = {"id", "category", "check_name", "resource_type", "resource_pattern", "severity", "cis_id"}
    categories = set()
    for item in findings:
        assert required_keys.issubset(item.keys()), f"Missing keys in expected item: {item.get('id')}"
        categories.add(item["category"])

    assert categories == {"S3", "IAM", "SECURITY_GROUP", "MONITORING"}


def test_perfect_matching():
    """Verify that full offline validation against synthetic testbed yields 100% accuracy."""
    report, summary_text = run_offline_validation()

    assert isinstance(report, ValidationReport)
    assert report.total_expected == 14
    assert report.total_actual == 14
    assert report.true_positives == 14
    assert report.false_positives == 0
    assert report.false_negatives == 0
    assert report.precision == 100.0
    assert report.recall == 100.0

    # Verify per-category results
    assert report.category_metrics["S3"].expected_count == 3
    assert report.category_metrics["S3"].true_positives == 3
    assert report.category_metrics["S3"].precision == 100.0
    assert report.category_metrics["S3"].recall == 100.0

    assert report.category_metrics["IAM"].expected_count == 4
    assert report.category_metrics["IAM"].true_positives == 4
    assert report.category_metrics["IAM"].precision == 100.0
    assert report.category_metrics["IAM"].recall == 100.0

    assert report.category_metrics["SECURITY_GROUP"].expected_count == 4
    assert report.category_metrics["SECURITY_GROUP"].true_positives == 4
    assert report.category_metrics["SECURITY_GROUP"].precision == 100.0
    assert report.category_metrics["SECURITY_GROUP"].recall == 100.0

    assert report.category_metrics["MONITORING"].expected_count == 3
    assert report.category_metrics["MONITORING"].true_positives == 3
    assert report.category_metrics["MONITORING"].precision == 100.0
    assert report.category_metrics["MONITORING"].recall == 100.0

    # Summary string contains synthetic notification and table
    assert "Synthetic Mock Environment" in summary_text
    assert "100.0%" in summary_text


def test_missing_expected_findings():
    """Verify that missing expected findings are flagged as False Negatives, reducing Recall."""
    expected = [
        {
            "id": "s3-public-policy",
            "category": "S3",
            "check_name": "S3 Bucket Public Access via Policy",
            "resource_type": "AWS::S3::Bucket",
            "resource_pattern": "cloudguard-test-pub-policy",
            "severity": "CRITICAL",
            "cis_id": "CIS-2.1.1",
        },
        {
            "id": "s3-bpa-disabled",
            "category": "S3",
            "check_name": "S3 Bucket Block Public Access Disabled",
            "resource_type": "AWS::S3::Bucket",
            "resource_pattern": "cloudguard-test-pub-acl",
            "severity": "HIGH",
            "cis_id": "CIS-2.1.2",
        },
    ]

    # Only 1 actual finding generated
    actual = [
        Finding(
            id="s3-public-policy-cloudguard-test-pub-policy",
            check_name="S3 Bucket Public Access via Policy",
            resource_type="AWS::S3::Bucket",
            resource_id="cloudguard-test-pub-policy",
            region="ap-south-1",
            severity="CRITICAL",
            exposure="PUBLIC",
            sensitivity="HIGH",
            evidence={},
            cis_id="CIS-2.1.1",
        )
    ]

    report = evaluate_validation(expected, actual)
    assert report.true_positives == 1
    assert report.false_positives == 0
    assert report.false_negatives == 1
    assert report.precision == 100.0
    assert report.recall == 50.0  # 1 / (1 + 1) = 50.0%
    assert len(report.unmatched_expected) == 1
    assert report.unmatched_expected[0]["id"] == "s3-bpa-disabled"


def test_unexpected_actual_findings():
    """Verify that unplanted actual findings are flagged as False Positives, reducing Precision."""
    expected = [
        {
            "id": "s3-public-policy",
            "category": "S3",
            "check_name": "S3 Bucket Public Access via Policy",
            "resource_type": "AWS::S3::Bucket",
            "resource_pattern": "cloudguard-test-pub-policy",
            "severity": "CRITICAL",
            "cis_id": "CIS-2.1.1",
        }
    ]

    actual = [
        Finding(
            id="s3-public-policy-cloudguard-test-pub-policy",
            check_name="S3 Bucket Public Access via Policy",
            resource_type="AWS::S3::Bucket",
            resource_id="cloudguard-test-pub-policy",
            region="ap-south-1",
            severity="CRITICAL",
            exposure="PUBLIC",
            sensitivity="HIGH",
            evidence={},
            cis_id="CIS-2.1.1",
        ),
        # Unexpected rogue finding
        Finding(
            id="s3-rogue-finding",
            check_name="S3 Bucket Missing Default Encryption",
            resource_type="AWS::S3::Bucket",
            resource_id="cloudguard-test-rogue-bucket",
            region="ap-south-1",
            severity="HIGH",
            exposure="INTERNAL",
            sensitivity="MEDIUM",
            evidence={},
            cis_id="CIS-2.1.3",
        ),
    ]

    report = evaluate_validation(expected, actual)
    assert report.true_positives == 1
    assert report.false_positives == 1
    assert report.false_negatives == 0
    assert report.precision == 50.0  # 1 / (1 + 1) = 50.0%
    assert report.recall == 100.0
    assert len(report.unmatched_actual) == 1
    assert report.unmatched_actual[0].id == "s3-rogue-finding"


def test_duplicate_matching_prevention():
    """Verify that multiple identical actual findings cannot match the same expected item twice."""
    expected = [
        {
            "id": "sg-open-ssh",
            "category": "SECURITY_GROUP",
            "check_name": "Security Group Ingress Allows Port 22 (SSH) from 0.0.0.0/0",
            "resource_type": "AWS::EC2::SecurityGroup",
            "resource_pattern": "cloudguard-test-open-ssh-sg",
            "severity": "CRITICAL",
            "cis_id": "CIS-5.2",
        }
    ]

    # Two duplicate findings for the same SG and port
    actual = [
        Finding(
            id="sg-open-22-sg-1111",
            check_name="Security Group Ingress Allows Port 22 (SSH) from 0.0.0.0/0",
            resource_type="AWS::EC2::SecurityGroup",
            resource_id="sg-1111",
            region="ap-south-1",
            severity="CRITICAL",
            exposure="PUBLIC",
            sensitivity="HIGH",
            evidence={"GroupName": "cloudguard-test-open-ssh-sg", "ExposedPort": 22},
            cis_id="CIS-5.2",
        ),
        Finding(
            id="sg-open-22-sg-1111-dup",
            check_name="Security Group Ingress Allows Port 22 (SSH) from 0.0.0.0/0",
            resource_type="AWS::EC2::SecurityGroup",
            resource_id="sg-1111",
            region="ap-south-1",
            severity="CRITICAL",
            exposure="PUBLIC",
            sensitivity="HIGH",
            evidence={"GroupName": "cloudguard-test-open-ssh-sg", "ExposedPort": 22},
            cis_id="CIS-5.2",
        ),
    ]

    report = evaluate_validation(expected, actual)
    assert report.true_positives == 1  # Only matched once
    assert report.false_positives == 1  # Duplicate is treated as FP
    assert report.false_negatives == 0
    assert report.precision == 50.0


def test_zero_denominator_metrics():
    """Verify convention: 0.0% is reported without ZeroDivisionError when denominator is zero."""
    # Case A: 0 expected, 0 actual
    report_a = evaluate_validation([], [])
    assert report_a.precision == 0.0
    assert report_a.recall == 0.0

    # Case B: 1 expected, 0 actual (TP=0, FP=0, FN=1 -> precision denominator is 0)
    expected_b = [{"id": "item-b", "category": "S3", "cis_id": "CIS-2.1.1", "resource_pattern": "b"}]
    report_b = evaluate_validation(expected_b, [])
    assert report_b.true_positives == 0
    assert report_b.false_positives == 0
    assert report_b.false_negatives == 1
    assert report_b.precision == 0.0  # (0 / 0) -> 0.0%
    assert report_b.recall == 0.0     # (0 / 1) -> 0.0%

    # Case C: 0 expected, 1 actual (TP=0, FP=1, FN=0 -> recall denominator is 0)
    actual_c = [
        Finding(
            id="item-c",
            check_name="Check",
            resource_type="AWS::S3::Bucket",
            resource_id="c",
            region="ap-south-1",
            severity="LOW",
            exposure="INTERNAL",
            sensitivity="LOW",
            evidence={},
        )
    ]
    report_c = evaluate_validation([], actual_c)
    assert report_c.true_positives == 0
    assert report_c.false_positives == 1
    assert report_c.false_negatives == 0
    assert report_c.precision == 0.0  # (0 / 1) -> 0.0%
    assert report_c.recall == 0.0     # (0 / 0) -> 0.0%


def test_security_group_port_specificity():
    """Verify matching doesn't classify findings as correct merely because their CIS IDs match."""
    # Expected item is MySQL port 3306 (CIS-5.4)
    expected_mysql = {
        "id": "sg-open-mysql",
        "category": "SECURITY_GROUP",
        "check_name": "Security Group Ingress Allows Database Port 3306 (MySQL) from 0.0.0.0/0",
        "resource_type": "AWS::EC2::SecurityGroup",
        "resource_pattern": "cloudguard-test-open-db-sg",
        "severity": "CRITICAL",
        "cis_id": "CIS-5.4",
    }

    # Finding for MSSQL port 1433 also shares CIS-5.4 on the same security group
    mssql_finding = Finding(
        id="sg-open-1433-sg-db",
        check_name="Security Group Ingress Allows Port 1433 (MSSQL) from 0.0.0.0/0",
        resource_type="AWS::EC2::SecurityGroup",
        resource_id="sg-db",
        region="ap-south-1",
        severity="CRITICAL",
        exposure="PUBLIC",
        sensitivity="CRITICAL",
        evidence={"GroupName": "cloudguard-test-open-db-sg", "ExposedPort": 1433},
        cis_id="CIS-5.4",
    )

    # Must NOT match despite matching SG name and CIS ID
    assert matches_finding(expected_mysql, mssql_finding) is False

    # Actual MySQL port 3306 finding MUST match
    mysql_finding = Finding(
        id="sg-open-3306-sg-db",
        check_name="Security Group Ingress Allows Port 3306 (MySQL/Aurora) from 0.0.0.0/0",
        resource_type="AWS::EC2::SecurityGroup",
        resource_id="sg-db",
        region="ap-south-1",
        severity="CRITICAL",
        exposure="PUBLIC",
        sensitivity="CRITICAL",
        evidence={"GroupName": "cloudguard-test-open-db-sg", "ExposedPort": 3306},
        cis_id="CIS-5.4",
    )
    assert matches_finding(expected_mysql, mysql_finding) is True


def test_offline_execution_without_aws_credentials(monkeypatch):
    """Verify execution runs purely offline without AWS credentials in environment."""
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)
    monkeypatch.delenv("AWS_PROFILE", raising=False)

    exit_code = main()
    assert exit_code == 0
