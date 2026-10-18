"""
Unit Tests for Stage 5: Risk Scoring Engine and CIS Benchmark Mapping.

Verifies:
1. Mathematical precision of the multiplicative risk formula (Score = Sev × Exp × Sens).
2. Descending ranking of findings to eliminate alert fatigue.
3. Accurate tagging of CIS AWS Foundations Benchmark control IDs.
"""

import sys
from pathlib import Path
import pytest

# Ensure project root is available in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cloudguard.models import Finding
from cloudguard.scoring import calculate_risk_score, score_and_rank_findings
from cloudguard.cis_mapping import tag_findings_with_cis, get_cis_id_for_check, CIS_CONTROLS_METADATA


def test_risk_formula_mathematical_precision():
    """Verify calculated risk scores match expected formula outputs."""
    # Critical flaw on Public Critical asset (e.g., Public DB or root admin key)
    # 10.0 * 2.0 * 2.5 = 50.0
    score_max = calculate_risk_score(severity="CRITICAL", exposure="PUBLIC", sensitivity="CRITICAL")
    assert score_max == 50.0

    # High flaw on Public High asset (e.g., S3 public BPA disabled)
    # 7.0 * 2.0 * 2.0 = 28.0
    score_pub_high = calculate_risk_score(severity="HIGH", exposure="PUBLIC", sensitivity="HIGH")
    assert score_pub_high == 28.0

    # Critical flaw on Internal Critical asset (e.g., Wildcard IAM admin role)
    # 10.0 * 1.0 * 2.5 = 25.0
    score_int_crit = calculate_risk_score(severity="CRITICAL", exposure="INTERNAL", sensitivity="CRITICAL")
    assert score_int_crit == 25.0

    # High flaw on Internal Medium asset (e.g., Unencrypted S3 bucket)
    # 7.0 * 1.0 * 1.5 = 10.5
    score_enc = calculate_risk_score(severity="HIGH", exposure="INTERNAL", sensitivity="MEDIUM")
    assert score_enc == 10.5

    # Medium flaw on Internal Medium asset (e.g., User without MFA)
    # 4.0 * 1.0 * 1.5 = 6.0
    score_mfa = calculate_risk_score(severity="MEDIUM", exposure="INTERNAL", sensitivity="MEDIUM")
    assert score_mfa == 6.0

    # Low flaw on Internal Low asset (e.g., Active key tracking)
    # 1.0 * 1.0 * 1.0 = 1.0
    score_min = calculate_risk_score(severity="LOW", exposure="INTERNAL", sensitivity="LOW")
    assert score_min == 1.0


def test_score_and_rank_orders_descending():
    """Verify that findings are correctly sorted from highest risk score to lowest."""
    f1 = Finding(
        id="f1", check_name="Low Risk", resource_type="AWS::S3::Bucket",
        resource_id="b1", region="ap-south-1", severity="LOW", exposure="INTERNAL",
        sensitivity="LOW", evidence={}
    )
    f2 = Finding(
        id="f2", check_name="Medium Risk", resource_type="AWS::IAM::User",
        resource_id="u1", region="global", severity="MEDIUM", exposure="INTERNAL",
        sensitivity="MEDIUM", evidence={}
    )
    f3 = Finding(
        id="f3", check_name="Critical Public Risk", resource_type="AWS::EC2::SecurityGroup",
        resource_id="sg1", region="ap-south-1", severity="CRITICAL", exposure="PUBLIC",
        sensitivity="CRITICAL", evidence={}
    )
    f4 = Finding(
        id="f4", check_name="High Public Risk", resource_type="AWS::S3::Bucket",
        resource_id="b2", region="ap-south-1", severity="HIGH", exposure="PUBLIC",
        sensitivity="HIGH", evidence={}
    )

    ranked = score_and_rank_findings([f1, f2, f3, f4])

    assert ranked[0].id == "f3"  # Score: 50.0
    assert ranked[1].id == "f4"  # Score: 28.0
    assert ranked[2].id == "f2"  # Score: 6.0
    assert ranked[3].id == "f1"  # Score: 1.0
    assert ranked[0].risk_score > ranked[1].risk_score > ranked[2].risk_score > ranked[3].risk_score


def test_cis_benchmark_mapping_all_checks():
    """Verify all implemented check titles map to their respective official CIS IDs."""
    test_cases = [
        ("S3 Bucket Public Access via Policy", "CIS-2.1.1"),
        ("S3 Bucket Block Public Access Disabled", "CIS-2.1.2"),
        ("S3 Bucket Public Access via ACL", "CIS-2.1.2"),
        ("IAM Policy Grants Wildcard Administrative Privileges (*:*)", "CIS-1.16"),
        ("IAM User Without MFA Enabled", "CIS-1.5"),
        ("IAM User Has Active Access Key Overdue for Rotation (>90 Days)", "CIS-1.14"),
        ("IAM Role Has Full Administrative Access", "CIS-1.16"),
        ("Security Group Ingress Allows Port 22 (SSH) from 0.0.0.0/0", "CIS-5.2"),
        ("Security Group Ingress Allows Port 3389 (RDP) from 0.0.0.0/0", "CIS-5.3"),
        ("Security Group Ingress Allows Database Port 3306 (MySQL) from 0.0.0.0/0", "CIS-5.4"),
        ("Security Group Ingress Allows Database Port 5432 (PostgreSQL) from 0.0.0.0/0", "CIS-5.4"),
        ("CloudTrail Not Enabled In All Regions", "CIS-3.1"),
        ("CloudTrail Log File Validation Disabled", "CIS-3.2"),
        ("Missing CloudWatch Metric Alarms for Critical Security Events in Audited Region", "CIS-3.4"),
    ]

    for check_name, expected_cis in test_cases:
        actual_cis = get_cis_id_for_check(check_name)
        assert actual_cis == expected_cis, f"Check '{check_name}' expected {expected_cis}, got {actual_cis}"
        # Ensure metadata exists for every mapped CIS control
        if actual_cis != "N/A":
            assert actual_cis in CIS_CONTROLS_METADATA


def test_tag_findings_with_cis_populates_findings():
    """Verify tag_findings_with_cis correctly mutates findings with cis_id."""
    findings = [
        Finding(
            id="test-1", check_name="S3 Bucket Public Access via Policy",
            resource_type="AWS::S3::Bucket", resource_id="my-bucket",
            region="ap-south-1", severity="CRITICAL", exposure="PUBLIC",
            sensitivity="HIGH", evidence={}, cis_id="N/A"
        ),
        Finding(
            id="test-2", check_name="IAM User Without MFA Enabled",
            resource_type="AWS::IAM::User", resource_id="alice",
            region="global", severity="MEDIUM", exposure="INTERNAL",
            sensitivity="MEDIUM", evidence={}, cis_id="N/A"
        )
    ]

    tagged = tag_findings_with_cis(findings)
    assert tagged[0].cis_id == "CIS-2.1.1"
    assert tagged[1].cis_id == "CIS-1.5"
