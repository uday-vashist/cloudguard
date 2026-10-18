"""
Unit Tests for Stage 4: Security Group and Monitoring Scanners.

Enables full offline verification of Security Group and Observability audits
against the test fixtures defined in the Terraform testbed.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock
import pytest
from botocore.exceptions import ClientError

# Ensure project root is available in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cloudguard.scanners.sg_scanner import scan_security_groups
from cloudguard.scanners.monitoring_scanner import scan_monitoring


# =============================================================================
# Security Group Scanner Tests
# =============================================================================

def test_sg_scanner_detects_open_ssh_port_22():
    """Verify detection of Port 22 open to 0.0.0.0/0."""
    mock_ec2 = MagicMock()
    mock_ec2.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-open-ssh-12345",
                "GroupName": "cloudguard-test-open-ssh-sg",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        "Ipv6Ranges": []
                    }
                ]
            }
        ]
    }
    # Mock paginator to yield this group
    paginator = MagicMock()
    paginator.paginate.return_value = [mock_ec2.describe_security_groups.return_value]
    mock_ec2.get_paginator.return_value = paginator

    findings = scan_security_groups(client=mock_ec2, region_name="ap-south-1")
    assert len(findings) == 1
    f = findings[0]
    assert "Port 22 (SSH)" in f.check_name
    assert f.severity == "CRITICAL"
    assert f.exposure == "PUBLIC"
    assert f.resource_id == "sg-open-ssh-12345"


def test_sg_scanner_detects_open_rdp_port_3389():
    """Verify detection of Port 3389 open to 0.0.0.0/0."""
    mock_ec2 = MagicMock()
    mock_ec2.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-open-rdp-67890",
                "GroupName": "cloudguard-test-open-rdp-sg",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 3389,
                        "ToPort": 3389,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        "Ipv6Ranges": []
                    }
                ]
            }
        ]
    }
    paginator = MagicMock()
    paginator.paginate.return_value = [mock_ec2.describe_security_groups.return_value]
    mock_ec2.get_paginator.return_value = paginator

    findings = scan_security_groups(client=mock_ec2, region_name="ap-south-1")
    assert len(findings) == 1
    f = findings[0]
    assert "Port 3389 (RDP)" in f.check_name
    assert f.severity == "CRITICAL"
    assert f.exposure == "PUBLIC"


def test_sg_scanner_detects_open_database_ports():
    """Verify detection of database ports (3306 MySQL and 5432 Postgres) open to 0.0.0.0/0."""
    mock_ec2 = MagicMock()
    mock_ec2.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-open-db-99999",
                "GroupName": "cloudguard-test-open-db-sg",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 3306,
                        "ToPort": 3306,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        "Ipv6Ranges": []
                    },
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 5432,
                        "ToPort": 5432,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        "Ipv6Ranges": []
                    }
                ]
            }
        ]
    }
    paginator = MagicMock()
    paginator.paginate.return_value = [mock_ec2.describe_security_groups.return_value]
    mock_ec2.get_paginator.return_value = paginator

    findings = scan_security_groups(client=mock_ec2, region_name="ap-south-1")
    assert len(findings) == 2
    ports = [f.evidence["ExposedPort"] for f in findings]
    assert 3306 in ports
    assert 5432 in ports
    for f in findings:
        assert f.sensitivity == "CRITICAL"
        assert f.exposure == "PUBLIC"


def test_sg_scanner_compliant_web_sg_produces_zero_findings():
    """Verify that HTTPS 443 web traffic produces 0 sensitive port findings."""
    mock_ec2 = MagicMock()
    mock_ec2.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-compliant-web-443",
                "GroupName": "cloudguard-test-compliant-web-sg",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 443,
                        "ToPort": 443,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        "Ipv6Ranges": []
                    }
                ]
            }
        ]
    }
    paginator = MagicMock()
    paginator.paginate.return_value = [mock_ec2.describe_security_groups.return_value]
    mock_ec2.get_paginator.return_value = paginator

    findings = scan_security_groups(client=mock_ec2, region_name="ap-south-1")
    assert len(findings) == 0, "Compliant HTTPS SG must produce 0 findings!"


def test_sg_scanner_restricted_cidr_produces_zero_findings():
    """Verify that sensitive port restricted to private internal CIDR produces 0 findings."""
    mock_ec2 = MagicMock()
    mock_ec2.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-internal-ssh",
                "GroupName": "internal-ssh-only",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": "10.0.0.0/16"}], # Internal only!
                        "Ipv6Ranges": []
                    }
                ]
            }
        ]
    }
    paginator = MagicMock()
    paginator.paginate.return_value = [mock_ec2.describe_security_groups.return_value]
    mock_ec2.get_paginator.return_value = paginator

    findings = scan_security_groups(client=mock_ec2, region_name="ap-south-1")
    assert len(findings) == 0, "Private internal CIDR must not be flagged as public exposure!"


# =============================================================================
# Monitoring Scanner Tests
# =============================================================================

def test_monitoring_scanner_detects_single_region_and_disabled_validation():
    """Verify detection of single-region trail and disabled log validation."""
    mock_ct = MagicMock()
    mock_ct.describe_trails.return_value = {
        "trailList": [
            {
                "Name": "cloudguard-test-insecure-trail",
                "TrailARN": "arn:aws:cloudtrail:ap-south-1:123456789012:trail/cloudguard-test-insecure-trail",
                "IsMultiRegionTrail": False,
                "LogFileValidationEnabled": False
            }
        ]
    }

    mock_cw = MagicMock()
    mock_cw.describe_alarms.return_value = {
        "MetricAlarms": [] # Missing alarms
    }

    findings = scan_monitoring(cloudtrail_client=mock_ct, cloudwatch_client=mock_cw, region_name="ap-south-1")
    check_names = [f.check_name for f in findings]

    assert "CloudTrail Not Enabled In All Regions" in check_names
    assert "CloudTrail Log File Validation Disabled" in check_names
    assert "Missing CloudWatch Metric Alarms for Critical Security Events in Audited Region" in check_names


def test_monitoring_scanner_does_not_infer_account_absence_from_empty_region():
    """An empty regional listing is unverified, not proof of no account trails."""
    mock_ct = MagicMock()
    mock_ct.describe_trails.return_value = {"trailList": []}

    mock_cw = MagicMock()
    mock_cw.describe_alarms.return_value = {"MetricAlarms": []}

    findings = scan_monitoring(cloudtrail_client=mock_ct, cloudwatch_client=mock_cw, region_name="ap-south-1")
    check_names = [f.check_name for f in findings]
    assert "CloudTrail Account Coverage Unverified: No Trails Visible in Audited Region" in check_names
    trail_observation = next(f for f in findings if f.check_name.startswith("CloudTrail Account Coverage"))
    assert trail_observation.severity == "INFO"
    assert trail_observation.risk_score == 0.0


def test_monitoring_scanner_marks_alarm_candidate_configuration_unverified():
    """A keyword-matched alarm is not treated as verified configuration."""
    mock_ct = MagicMock()
    mock_ct.describe_trails.return_value = {
        "trailList": [
            {
                "Name": "secure-global-trail",
                "IsMultiRegionTrail": True,
                "LogFileValidationEnabled": True
            }
        ]
    }

    mock_cw = MagicMock()
    mock_cw.describe_alarms.return_value = {
        "MetricAlarms": [
            {
                "AlarmName": "RootAccountUsageAlarm",
                "MetricName": "RootAccountUsageCount"
            }
        ]
    }

    findings = scan_monitoring(cloudtrail_client=mock_ct, cloudwatch_client=mock_cw, region_name="ap-south-1")
    assert len(findings) == 1
    assert findings[0].severity == "INFO"
    assert "Configuration Unverified" in findings[0].check_name


def test_sg_scanner_raises_on_describe_security_groups_client_error():
    """Verify that sg_scanner raises ClientError when describe_security_groups fails (e.g. UnauthorizedOperation)."""
    mock_ec2 = MagicMock()
    mock_ec2.get_paginator.side_effect = AttributeError("No paginator")
    mock_ec2.describe_security_groups.side_effect = ClientError(
        {"Error": {"Code": "UnauthorizedOperation", "Message": "You are not authorized"}},
        "DescribeSecurityGroups"
    )
    with pytest.raises(ClientError):
        scan_security_groups(client=mock_ec2, region_name="ap-south-1")


def test_monitoring_scanner_raises_on_describe_trails_client_error():
    """Verify that monitoring_scanner raises ClientError when describe_trails fails."""
    mock_ct = MagicMock()
    mock_ct.describe_trails.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}},
        "DescribeTrails"
    )
    mock_cw = MagicMock()
    with pytest.raises(ClientError):
        scan_monitoring(cloudtrail_client=mock_ct, cloudwatch_client=mock_cw, region_name="ap-south-1")

