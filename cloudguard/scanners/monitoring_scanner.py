"""
CloudGuard Observability & Monitoring Scanner.

Audits AWS CloudTrail and CloudWatch configurations against security monitoring baselines:
1. CloudTrail Multi-Region Coverage (IsMultiRegionTrail = True)
2. CloudTrail Log File Validation (LogFileValidationEnabled = True)
3. CloudWatch Metric Alarms for Critical Security Events (Root usage, unauthorized calls, MFA failure)

VIVA CONCEPTS:
- Visibility & Forensic Integrity: If an attacker compromises an account in an unmonitored region,
  a single-region CloudTrail will be blind to the intrusion. Furthermore, without Log File Validation
  (SHA-256 digests), attackers can delete or modify audit logs without detection.
- Read-Only Compliance: Only calls cloudtrail.describe_trails and cloudwatch.describe_alarms.
"""

from typing import Any, Dict, List, Optional
from botocore.exceptions import ClientError
from cloudguard.aws_session import get_client
from cloudguard.models import Finding

# Common keywords in alarm names/metrics indicating security event monitoring
SECURITY_ALARM_KEYWORDS = [
    "root", "unauthorized", "mfa", "iampolicy", "cloudtrail", "kms", "securitygroup", "networkacl"
]


def check_cloudtrail_trails(cloudtrail_client: Any, region: str) -> List[Finding]:
    """
    Audits CloudTrail for multi-region logging and cryptographic log file validation.
    """
    findings: List[Finding] = []

    try:
        resp = cloudtrail_client.describe_trails()
        trails = resp.get("trailList", [])
    except ClientError as e:
        print(f"[WARN] CloudTrail describe_trails failed: {e}")
        return findings

    # Case A: No trails configured in the account
    if not trails:
        findings.append(Finding(
            id="cloudtrail-no-trails-configured",
            check_name="No CloudTrail Trails Configured in AWS Account",
            resource_type="AWS::CloudTrail::Trail",
            resource_id="None",
            region=region,
            severity="CRITICAL",
            exposure="INTERNAL",
            sensitivity="CRITICAL",
            evidence={"trailList": []},
            cis_id="CIS-3.1",
            remediation=(
                "Create a multi-region CloudTrail trail:\n"
                "aws cloudtrail create-trail --name account-audit-trail "
                "--s3-bucket-name <audit-bucket-name> --is-multi-region-trail\n"
                "aws cloudtrail start-logging --name account-audit-trail"
            )
        ))
        return findings

    # Case B: Audit each existing trail
    for trail in trails:
        trail_name = trail.get("Name", "")
        trail_arn = trail.get("TrailARN", trail_name)
        is_multi_region = trail.get("IsMultiRegionTrail", False)
        log_validation = trail.get("LogFileValidationEnabled", False)

        # 1. Multi-region check
        if not is_multi_region:
            findings.append(Finding(
                id=f"cloudtrail-single-region-{trail_name}",
                check_name="CloudTrail Not Enabled In All Regions",
                resource_type="AWS::CloudTrail::Trail",
                resource_id=trail_name,
                region=region,
                severity="HIGH",
                exposure="INTERNAL",
                sensitivity="HIGH",
                evidence={
                    "TrailName": trail_name,
                    "TrailARN": trail_arn,
                    "IsMultiRegionTrail": False
                },
                cis_id="CIS-3.1",
                remediation=(
                    f"Enable multi-region logging for trail {trail_name}:\n"
                    f"aws cloudtrail update-trail --name {trail_name} --is-multi-region-trail"
                )
            ))

        # 2. Log File Validation check
        if not log_validation:
            findings.append(Finding(
                id=f"cloudtrail-validation-disabled-{trail_name}",
                check_name="CloudTrail Log File Validation Disabled",
                resource_type="AWS::CloudTrail::Trail",
                resource_id=trail_name,
                region=region,
                severity="MEDIUM",
                exposure="INTERNAL",
                sensitivity="MEDIUM",
                evidence={
                    "TrailName": trail_name,
                    "TrailARN": trail_arn,
                    "LogFileValidationEnabled": False
                },
                cis_id="CIS-3.2",
                remediation=(
                    f"Enable cryptographic log file validation for trail {trail_name}:\n"
                    f"aws cloudtrail update-trail --name {trail_name} --enable-log-file-validation"
                )
            ))

    return findings


def check_cloudwatch_alarms(cloudwatch_client: Any, region: str) -> List[Finding]:
    """
    Audits CloudWatch for essential security alarms (Root account usage, unauthorized API calls).
    """
    findings: List[Finding] = []

    try:
        resp = cloudwatch_client.describe_alarms()
        alarms = resp.get("MetricAlarms", [])
    except ClientError as e:
        print(f"[WARN] CloudWatch describe_alarms failed: {e}")
        return findings

    # Check if any security alarms exist
    has_security_alarm = False
    for a in alarms:
        alarm_name = a.get("AlarmName", "").lower()
        metric_name = a.get("MetricName", "").lower()
        if any(kw in alarm_name or kw in metric_name for kw in SECURITY_ALARM_KEYWORDS):
            has_security_alarm = True
            break

    if not has_security_alarm or len(alarms) == 0:
        findings.append(Finding(
            id="cloudwatch-missing-alarms",
            check_name="Missing CloudWatch Metric Alarms for Critical Security Events",
            resource_type="AWS::CloudWatch::Alarm",
            resource_id="global",
            region=region,
            severity="MEDIUM",
            exposure="INTERNAL",
            sensitivity="HIGH",
            evidence={
                "TotalMetricAlarms": len(alarms),
                "HasSecurityAlarm": has_security_alarm
            },
            cis_id="CIS-3.4",
            remediation=(
                "Create CloudWatch metric filters and alarms for critical events:\n"
                "1. Root Account Usage\n"
                "2. Unauthorized API calls (errorCode = '*UnauthorizedOperation' or 'AccessDenied')\n"
                "3. Console sign-in without MFA"
            )
        ))

    return findings


def scan_monitoring(
    cloudtrail_client: Optional[Any] = None,
    cloudwatch_client: Optional[Any] = None,
    region_name: str = "ap-south-1"
) -> List[Finding]:
    """
    Main Monitoring scanner entry point.
    Audits CloudTrail logging and CloudWatch security metric alarms.
    """
    ct_client = cloudtrail_client or get_client("cloudtrail", region_name=region_name)
    cw_client = cloudwatch_client or get_client("cloudwatch", region_name=region_name)

    findings: List[Finding] = []
    findings.extend(check_cloudtrail_trails(ct_client, region_name))
    findings.extend(check_cloudwatch_alarms(cw_client, region_name))

    return findings
