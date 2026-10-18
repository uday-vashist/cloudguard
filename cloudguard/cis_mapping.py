"""
CloudGuard CIS AWS Foundations Benchmark Control Mapping.

Maps implemented security audit checks to official CIS AWS Foundations Benchmark
control identifiers. Strictly limited ONLY to checks actually implemented in CloudGuard.

VIVA CONCEPTS:
- What is CIS Benchmark?
  The Center for Internet Security (CIS) AWS Foundations Benchmark is the industry-standard
  security configuration baseline for securing Amazon Web Services accounts.
- Why Map to CIS?
  Enterprise security teams measure compliance against standard frameworks (CIS, NIST, SOC 2).
  By tagging findings with official CIS control IDs, CloudGuard translates raw configuration
  flaws into compliance audit evidence.
"""

from typing import Dict, List
from cloudguard.models import Finding

# Official CIS AWS Foundations Benchmark Control Metadata (Only implemented checks)
CIS_CONTROLS_METADATA: Dict[str, Dict[str, str]] = {
    "CIS-1.5": {
        "title": "Ensure MFA is enabled for all IAM users",
        "section": "1. Identity and Access Management",
        "description": "Multi-Factor Authentication adds a critical second layer of defense against compromised credentials."
    },
    "CIS-1.14": {
        "title": "Ensure access keys are rotated every 90 days or less",
        "section": "1. Identity and Access Management",
        "description": "Rotating access keys periodically restricts the window of opportunity for exposed or stolen API keys."
    },
    "CIS-1.16": {
        "title": "Ensure IAM policies do not allow full '*:*' administrative privileges",
        "section": "1. Identity and Access Management",
        "description": "Over-privileged wildcard permissions violate the principle of least privilege and expand attack blast radius."
    },
    "CIS-2.1.1": {
        "title": "Ensure S3 Bucket Policy does not grant public access",
        "section": "2. Storage",
        "description": "Bucket policies granting Principal '*' allow unauthenticated internet access to stored objects."
    },
    "CIS-2.1.2": {
        "title": "Ensure S3 Block Public Access is enabled for all buckets and ACLs",
        "section": "2. Storage",
        "description": "Centralized Block Public Access overrides insecure bucket policies and legacy ACLs."
    },
    "CIS-3.1": {
        "title": "Ensure CloudTrail is enabled across all regions",
        "section": "3. Logging & Monitoring",
        "description": "Multi-region trails ensure security events in any AWS region are captured without blind spots."
    },
    "CIS-3.2": {
        "title": "Ensure CloudTrail log file validation is enabled",
        "section": "3. Logging & Monitoring",
        "description": "Log file validation generates SHA-256 digital signatures to verify that logs have not been tampered with or deleted."
    },
    "CIS-3.4": {
        "title": "Ensure a metric alarm exists for unauthorized API calls and root account usage",
        "section": "3. Logging & Monitoring",
        "description": "CloudWatch alarms alert operations teams immediately when critical or unauthorized activity occurs."
    },
    "CIS-5.2": {
        "title": "Ensure no security groups allow ingress from 0.0.0.0/0 to remote admin port 22 (SSH)",
        "section": "5. Networking",
        "description": "SSH access from 0.0.0.0/0 exposes servers to automated credential brute-forcing and vulnerability scanning."
    },
    "CIS-5.3": {
        "title": "Ensure no security groups allow ingress from 0.0.0.0/0 to remote admin port 3389 (RDP)",
        "section": "5. Networking",
        "description": "RDP access open to the public internet enables remote graphical desktop brute-force compromises."
    },
    "CIS-5.4": {
        "title": "Ensure no security groups allow ingress from 0.0.0.0/0 to sensitive database ports",
        "section": "5. Networking",
        "description": "Database ports (MySQL, PostgreSQL, MSSQL, MongoDB) must reside in private subnets with no direct public route."
    },
}

# Rule table mapping check names / prefixes to CIS Control IDs
CHECK_TO_CIS_MAP = {
    "S3 Bucket Public Access via Policy": "CIS-2.1.1",
    "S3 Bucket Block Public Access Disabled": "CIS-2.1.2",
    "S3 Bucket Public Access via ACL": "CIS-2.1.2",
    "IAM Policy Grants Wildcard Administrative Privileges (*:*)": "CIS-1.16",
    "IAM User Without MFA Enabled": "CIS-1.5",
    "IAM User Has Active Access Key Overdue for Rotation (>90 Days)": "CIS-1.14",
    "IAM Role Has Full Administrative Access": "CIS-1.16",
    "CloudTrail Not Enabled In All Regions": "CIS-3.1",
    "No CloudTrail Trails Configured in AWS Account": "CIS-3.1",
    "CloudTrail Log File Validation Disabled": "CIS-3.2",
    "Missing CloudWatch Metric Alarms for Critical Security Events in Audited Region": "CIS-3.4",
}


def get_cis_id_for_check(check_name: str) -> str:
    """Lookup CIS control ID for a check title, including port matching."""
    # 1. Exact match
    if check_name in CHECK_TO_CIS_MAP:
        return CHECK_TO_CIS_MAP[check_name]

    # 2. Key rotation partial match
    if "Active Access Key Overdue for Rotation" in check_name:
        return "CIS-1.14"

    # 3. Security Group Port matching
    if "Port 22 (SSH)" in check_name:
        return "CIS-5.2"
    if "Port 3389 (RDP)" in check_name:
        return "CIS-5.3"
    if any(db in check_name for db in ("Database Port", "3306", "5432", "1433", "27017", "6379", "1521")):
        return "CIS-5.4"

    return "N/A"


def tag_findings_with_cis(findings: List[Finding]) -> List[Finding]:
    """
    Populates the cis_id field on all Finding objects in-place.
    Only tags checks with verified, actually implemented CIS controls.
    """
    for finding in findings:
        if finding.cis_id == "N/A" or not finding.cis_id:
            finding.cis_id = get_cis_id_for_check(finding.check_name)
    return findings
