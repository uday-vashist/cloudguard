"""
Unit Tests for CloudGuard End-to-End Pipeline & CLI Orchestrator.

Verifies:
1. Full audit pipeline execution: Session -> Scanners -> CIS Mapping -> Scoring -> Report.
2. Clean audit execution when zero misconfigurations are discovered.
3. Scanner failure boundary: Aborting report generation when zero findings are gathered
   due to scanner errors (prevents false "clean audit" reports).
4. Scanner failure handling with partial findings: Generates partial report with clear warning.
5. Missing AWS profile and missing credentials error handling.
6. CLI argument dispatching (--smoke-test vs. full audit mode).
7. Verified offline: Zero live AWS calls, complete reliance on mocks.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
from botocore.exceptions import ProfileNotFound, NoCredentialsError

from cloudguard.models import Finding
from cloudguard.main import run_audit, main


def _create_dummy_finding(check_name: str, res_id: str, severity: str = "HIGH") -> Finding:
    return Finding(
        id=f"test-{res_id}",
        check_name=check_name,
        resource_type="AWS::S3::Bucket",
        resource_id=res_id,
        region="ap-south-1",
        severity=severity,
        exposure="PUBLIC",
        sensitivity="HIGH",
        evidence={"Status": "Active"},
    )


def test_pipeline_run_audit_success(tmp_path: Path):
    """Verify end-to-end audit execution when all scanners succeed."""
    mock_session = MagicMock()
    mock_client = MagicMock()
    mock_session.client.return_value = mock_client

    out_file = tmp_path / "reports" / "audit.html"

    sample_s3 = [_create_dummy_finding("S3 Bucket Public Access via Policy", "bucket-1", "CRITICAL")]
    sample_iam = [_create_dummy_finding("IAM User Without MFA Enabled", "user-1", "MEDIUM")]
    sample_sg = [_create_dummy_finding("Security Group Ingress Allows Port 22 (SSH) from 0.0.0.0/0", "sg-1", "CRITICAL")]
    sample_mon = [_create_dummy_finding("CloudTrail Not Enabled In All Regions", "trail-1", "HIGH")]

    with patch("cloudguard.main.scan_s3", return_value=sample_s3) as p_s3, \
         patch("cloudguard.main.scan_iam", return_value=sample_iam) as p_iam, \
         patch("cloudguard.main.scan_security_groups", return_value=sample_sg) as p_sg, \
         patch("cloudguard.main.scan_monitoring", return_value=sample_mon) as p_mon:

        exit_code = run_audit(
            profile="test-profile",
            region="ap-south-1",
            output_path=str(out_file),
            session=mock_session,
        )

        assert exit_code == 0
        assert out_file.exists()

        # Verify all scanners were called with session clients
        assert p_s3.called
        assert p_iam.called
        assert p_sg.called
        assert p_mon.called

        # Verify report content contains scored and tagged findings
        content = out_file.read_text(encoding="utf-8")
        assert "bucket-1" in content
        assert "user-1" in content
        assert "sg-1" in content
        assert "trail-1" in content
        assert "CIS-2.1.1" in content  # S3 mapped CIS ID
        assert "CIS-1.5" in content    # IAM mapped CIS ID
        assert "PARTIAL AUDIT" not in content


def test_pipeline_run_audit_clean_environment(tmp_path: Path):
    """Verify pipeline generates clean-audit report when 0 misconfigurations are found."""
    mock_session = MagicMock()
    mock_session.client.return_value = MagicMock()

    out_file = tmp_path / "clean_audit.html"

    with patch("cloudguard.main.scan_s3", return_value=[]), \
         patch("cloudguard.main.scan_iam", return_value=[]), \
         patch("cloudguard.main.scan_security_groups", return_value=[]), \
         patch("cloudguard.main.scan_monitoring", return_value=[]):

        exit_code = run_audit(
            profile="test-profile",
            region="ap-south-1",
            output_path=str(out_file),
            session=mock_session,
        )

        assert exit_code == 0
        assert out_file.exists()
        content = out_file.read_text(encoding="utf-8")
        assert "Zero Misconfigurations Detected" in content


def test_scanner_failure_aborts_clean_report(tmp_path: Path):
    """Verify that when a scanner fails and 0 findings are collected, report generation is skipped."""
    mock_session = MagicMock()
    mock_session.client.return_value = MagicMock()

    out_file = tmp_path / "should_not_exist.html"

    with patch("cloudguard.main.scan_s3", side_effect=RuntimeError("S3 AccessDenied")), \
         patch("cloudguard.main.scan_iam", return_value=[]), \
         patch("cloudguard.main.scan_security_groups", return_value=[]), \
         patch("cloudguard.main.scan_monitoring", return_value=[]):

        exit_code = run_audit(
            profile="test-profile",
            region="ap-south-1",
            output_path=str(out_file),
            session=mock_session,
        )

        # Audit must fail and report must NOT be generated
        assert exit_code == 1
        assert not out_file.exists(), "Clean-audit report must NOT be generated when a scanner fails!"


def test_scanner_failure_with_partial_findings(tmp_path: Path):
    """Verify that when a scanner fails but other scanners found issues, a partial report is written with warning."""
    mock_session = MagicMock()
    mock_session.client.return_value = MagicMock()

    out_file = tmp_path / "partial_report.html"
    iam_finding = [_create_dummy_finding("IAM User Without MFA Enabled", "user-1", "MEDIUM")]

    with patch("cloudguard.main.scan_s3", side_effect=RuntimeError("S3 Network Timeout")), \
         patch("cloudguard.main.scan_iam", return_value=iam_finding), \
         patch("cloudguard.main.scan_security_groups", return_value=[]), \
         patch("cloudguard.main.scan_monitoring", return_value=[]):

        exit_code = run_audit(
            profile="test-profile",
            region="ap-south-1",
            output_path=str(out_file),
            session=mock_session,
        )

        # Non-zero exit code because audit had errors
        assert exit_code == 1
        # Partial report should exist
        assert out_file.exists()
        content = out_file.read_text(encoding="utf-8")
        assert "user-1" in content
        assert "PARTIAL AUDIT" in content
        assert "S3 Storage" in content


def test_missing_profile_error(capsys):
    """Verify clear error handling when AWS profile is missing."""
    with patch("cloudguard.main.get_session", side_effect=ProfileNotFound(profile="missing-profile")):
        exit_code = run_audit(profile="missing-profile")
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "AWS profile 'missing-profile' was not found" in captured.out


def test_missing_credentials_error(capsys):
    """Verify clear error handling when AWS credentials are not found."""
    with patch("cloudguard.main.get_session", side_effect=NoCredentialsError()):
        exit_code = run_audit(profile="cloudguard")
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "No AWS credentials found" in captured.out


def test_main_cli_smoke_test_dispatch():
    """Verify CLI --smoke-test flag invokes run_smoke_test."""
    with patch("cloudguard.main.run_smoke_test", return_value=0) as p_smoke:
        exit_code = main(["--smoke-test", "--profile", "my-test-profile", "--region", "us-east-1"])
        assert exit_code == 0
        p_smoke.assert_called_once_with("my-test-profile", "us-east-1")


def test_main_cli_audit_dispatch():
    """Verify CLI invokes run_audit with parsed arguments."""
    with patch("cloudguard.main.run_audit", return_value=0) as p_audit:
        exit_code = main(["--profile", "prod-profile", "--region", "ap-south-1", "--output", "custom/report.html"])
        assert exit_code == 0
        p_audit.assert_called_once_with(
            profile="prod-profile",
            region="ap-south-1",
            output_path="custom/report.html",
        )


def test_main_cli_demo_dispatch(tmp_path: Path):
    """Verify CLI --demo invokes run_audit in demo mode without AWS credentials."""
    out_file = tmp_path / "demo_report.html"
    exit_code = main(["--demo", "--output", str(out_file)])
    assert exit_code == 0
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "cloudguard (demo testbed)" in content
    assert "CRITICAL" in content


def test_main_cli_demo_smoke_test_dispatch():
    """Verify CLI --smoke-test --demo executes offline mock authentication."""
    with patch("cloudguard.main.run_smoke_test", return_value=0) as p_smoke:
        exit_code = main(["--smoke-test", "--demo"])
        assert exit_code == 0
        p_smoke.assert_called_once_with("cloudguard", "ap-south-1", demo=True)

