"""
Unit Tests for Stage 6: HTML Report Generator.

Verifies:
1. Generation of standalone, self-contained HTML reports for normal finding sets.
2. Graceful rendering of clean audits with empty finding sets (0 findings).
3. Automatic creation of parent directories for arbitrary output paths.
4. Precision of executive summary metrics (severity counts and maximum risk score).
5. Strict HTML escaping of untrusted evidence, check names, and resource identifiers (XSS safety).
6. Faithful representation of remediation commands without invented actions.
7. Accurate integration of CIS Foundations Benchmark metadata.
"""

from pathlib import Path
import pytest

from cloudguard.models import Finding
from cloudguard.report import generate_html_report
from cloudguard.cis_mapping import CIS_CONTROLS_METADATA


def _create_sample_findings():
    """Helper to generate a realistic set of multi-severity findings."""
    f1 = Finding(
        id="s3-public-policy-test-bucket",
        check_name="S3 Bucket Public Access via Policy",
        resource_type="AWS::S3::Bucket",
        resource_id="test-public-bucket",
        region="ap-south-1",
        severity="CRITICAL",
        exposure="PUBLIC",
        sensitivity="HIGH",
        evidence={"PolicyStatus": {"IsPublic": True}},
        cis_id="CIS-2.1.1",
        remediation="aws s3api delete-bucket-policy --bucket test-public-bucket",
        risk_score=40.0,
    )
    f2 = Finding(
        id="sg-open-ssh-test-sg",
        check_name="Security Group Ingress Allows Port 22 (SSH) from 0.0.0.0/0",
        resource_type="AWS::EC2::SecurityGroup",
        resource_id="sg-0123456789abcdef0",
        region="ap-south-1",
        severity="CRITICAL",
        exposure="PUBLIC",
        sensitivity="HIGH",
        evidence={"IpPermissions": [{"FromPort": 22, "CidrIp": "0.0.0.0/0"}]},
        cis_id="CIS-5.2",
        remediation="aws ec2 revoke-security-group-ingress --group-id sg-0123456789abcdef0 --port 22",
        risk_score=28.0,
    )
    f3 = Finding(
        id="iam-user-no-mfa-alice",
        check_name="IAM User Without MFA Enabled",
        resource_type="AWS::IAM::User",
        resource_id="alice",
        region="global",
        severity="MEDIUM",
        exposure="INTERNAL",
        sensitivity="MEDIUM",
        evidence={"MFADevices": []},
        cis_id="CIS-1.5",
        remediation="aws iam create-virtual-mfa-device --virtual-mfa-device-name alice-mfa",
        risk_score=6.0,
    )
    f4 = Finding(
        id="iam-active-key-bob",
        check_name="IAM User Has Active Access Key",
        resource_type="AWS::IAM::User",
        resource_id="bob",
        region="global",
        severity="LOW",
        exposure="INTERNAL",
        sensitivity="LOW",
        evidence={"AccessKeyId": "AKIAEXAMPLE"},
        cis_id="CIS-1.14",
        remediation="",
        risk_score=1.0,
    )
    return [f1, f2, f3, f4]


def test_generate_html_report_normal_findings(tmp_path: Path):
    """Verify normal findings produce a valid, self-contained HTML report with all required sections."""
    findings = _create_sample_findings()
    out_file = tmp_path / "reports" / "audit_report.html"

    result_path = generate_html_report(findings, output_path=str(out_file))

    assert Path(result_path).exists()
    assert result_path == str(out_file.resolve())

    content = out_file.read_text(encoding="utf-8")

    # Document structure assertions
    assert "<!DOCTYPE html>" in content
    assert "<title>CloudGuard Security Audit Report</title>" in content
    assert "CloudGuard Security Audit Report" in content

    # Finding content assertions
    assert "S3 Bucket Public Access via Policy" in content
    assert "test-public-bucket" in content
    assert "sg-0123456789abcdef0" in content
    assert "alice" in content
    assert "bob" in content

    # CIS ID assertions
    assert "CIS-2.1.1" in content
    assert "CIS-5.2" in content
    assert "CIS-1.5" in content

    # Evidence and remediation assertions
    assert "PolicyStatus" in content
    assert "aws s3api delete-bucket-policy" in content

    # Offline requirement check (no external CDNs)
    assert "https://cdn." not in content
    assert "https://fonts.googleapis.com" not in content
    assert "https://cdnjs.cloudflare.com" not in content


def test_generate_html_report_empty_findings(tmp_path: Path):
    """Verify graceful handling of an empty findings list (clean audit state)."""
    out_file = tmp_path / "reports" / "clean_report.html"

    result_path = generate_html_report([], output_path=str(out_file))

    assert Path(result_path).exists()
    content = out_file.read_text(encoding="utf-8")

    # Clean audit assertions
    assert "Zero Misconfigurations Detected" in content
    assert "Total Findings" in content
    assert ">0<" in content  # Total count is 0
    assert "No confirmed misconfigurations were detected in the checks that completed." in content


def test_output_directory_auto_creation(tmp_path: Path):
    """Verify parent directories are created automatically for nested output paths."""
    nested_path = tmp_path / "deeply" / "nested" / "custom_dir" / "report.html"
    assert not nested_path.parent.exists()

    result_path = generate_html_report([], output_path=str(nested_path))

    assert nested_path.parent.exists()
    assert Path(result_path).exists()


def test_summary_metrics_precision(tmp_path: Path):
    """Verify executive summary counts and maximum risk score match finding properties."""
    findings = _create_sample_findings()
    out_file = tmp_path / "metrics_report.html"

    generate_html_report(findings, output_path=str(out_file))
    content = out_file.read_text(encoding="utf-8")

    # Summary cards check:
    # 2 CRITICAL, 0 HIGH, 1 MEDIUM, 1 LOW, total = 4
    # Max risk score = 40.0
    assert "Total Findings" in content
    assert ">4<" in content  # Total findings count
    assert ">2<" in content  # Critical count
    assert ">0<" in content  # High count
    assert ">1<" in content  # Medium and Low count
    assert "40.0" in content  # Max risk score


def test_html_escaping_untrusted_content(tmp_path: Path):
    """Verify strict escaping of untrusted finding contents to prevent XSS injection."""
    malicious_finding = Finding(
        id="xss-test-id",
        check_name="<script>alert('check_xss')</script>",
        resource_type="AWS::S3::Bucket",
        resource_id="<img src=x onerror=alert('res_xss')>",
        region="ap-south-1",
        severity="HIGH",
        exposure="PUBLIC",
        sensitivity="CRITICAL",
        evidence={"payload": "<script>alert('evidence_xss')</script>"},
        cis_id="CIS-2.1.1",
        remediation="<svg onload=alert('remediation_xss')>",
        risk_score=35.0,
    )

    out_file = tmp_path / "xss_report.html"
    generate_html_report([malicious_finding], output_path=str(out_file))
    content = out_file.read_text(encoding="utf-8")

    # Raw script tags must NOT appear unescaped in HTML
    assert "<script>alert('check_xss')</script>" not in content
    assert "<img src=x onerror=alert('res_xss')>" not in content
    assert "<script>alert('evidence_xss')</script>" not in content
    assert "<svg onload=alert('remediation_xss')>" not in content

    # Escaped versions must be present
    assert "&lt;script&gt;alert(&#39;check_xss&#39;)&lt;/script&gt;" in content or "&lt;script&gt;" in content
    assert "&lt;img src=x" in content or "&lt;img" in content
    assert "&lt;svg" in content


def test_remediation_display_boundary(tmp_path: Path):
    """Verify remediation is only displayed when present and shows fallback when empty."""
    f_with_rem = Finding(
        id="f-rem",
        check_name="Check with Remediation",
        resource_type="AWS::S3::Bucket",
        resource_id="bucket-1",
        region="ap-south-1",
        severity="MEDIUM",
        exposure="INTERNAL",
        sensitivity="MEDIUM",
        evidence={},
        remediation="aws s3api put-bucket-encryption --bucket bucket-1",
    )
    f_without_rem = Finding(
        id="f-no-rem",
        check_name="Check without Remediation",
        resource_type="AWS::S3::Bucket",
        resource_id="bucket-2",
        region="ap-south-1",
        severity="LOW",
        exposure="INTERNAL",
        sensitivity="LOW",
        evidence={},
        remediation="",
    )

    out_file = tmp_path / "rem_report.html"
    generate_html_report([f_with_rem, f_without_rem], output_path=str(out_file))
    content = out_file.read_text(encoding="utf-8")

    assert "aws s3api put-bucket-encryption --bucket bucket-1" in content
    assert "No remediation guidance specified for this finding." in content


def test_cis_metadata_integration(tmp_path: Path):
    """Verify official CIS title metadata is rendered when a known CIS ID is present."""
    finding = Finding(
        id="cis-test",
        check_name="S3 Bucket Public Access via Policy",
        resource_type="AWS::S3::Bucket",
        resource_id="my-bucket",
        region="ap-south-1",
        severity="CRITICAL",
        exposure="PUBLIC",
        sensitivity="HIGH",
        evidence={},
        cis_id="CIS-2.1.1",
        risk_score=40.0,
    )

    out_file = tmp_path / "cis_report.html"
    generate_html_report([finding], output_path=str(out_file))
    content = out_file.read_text(encoding="utf-8")

    expected_cis_title = CIS_CONTROLS_METADATA["CIS-2.1.1"]["title"]
    assert expected_cis_title in content


def test_generate_html_report_partial_audit_warning(tmp_path: Path):
    """Verify that when failed_scanners is passed, the HTML report visibly renders a partial audit warning."""
    findings = _create_sample_findings()
    out_file = tmp_path / "partial_audit_report.html"

    generate_html_report(
        findings=findings,
        output_path=str(out_file),
        failed_scanners=["S3 Storage", "IAM Identity"],
    )
    content = out_file.read_text(encoding="utf-8")

    assert "PARTIAL AUDIT" in content
    assert "Some scanners failed; this report may not include all findings." in content
    assert "S3 Storage" in content
    assert "IAM Identity" in content


def test_generate_html_report_complete_audit_no_warning(tmp_path: Path):
    """Verify that a complete audit without failed scanners does NOT render a partial audit warning."""
    findings = _create_sample_findings()
    out_file = tmp_path / "complete_audit_report.html"

    # Default None or empty list
    generate_html_report(findings=findings, output_path=str(out_file), failed_scanners=None)
    content = out_file.read_text(encoding="utf-8")

    assert "PARTIAL AUDIT" not in content
    assert "Some scanners failed" not in content


def test_generate_html_report_partial_audit_escapes_xss(tmp_path: Path):
    """Verify that failed scanner names with HTML/script characters are properly escaped."""
    findings = _create_sample_findings()
    out_file = tmp_path / "xss_partial_report.html"

    generate_html_report(
        findings=findings,
        output_path=str(out_file),
        failed_scanners=["<script>alert('scanner_xss')</script>"],
    )
    content = out_file.read_text(encoding="utf-8")

    assert "<script>alert('scanner_xss')</script>" not in content
    assert "&lt;script&gt;alert(&#39;scanner_xss&#39;)&lt;/script&gt;" in content or "&lt;script&gt;" in content
