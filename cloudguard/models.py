"""
Data models for CloudGuard findings and audit records.

Why a dataclass?
1. Clean, typed data contract between scanners, scoring, and reporting.
2. Zero external dependencies (built into Python standard library).
3. Easily serialized to JSON for automated validation tests and viva demonstration.
Alternative considered:
- Dicts: Fragile, prone to typos (e.g., 'sev' vs 'severity'), no IDE autocompletion.
- Pydantic: Powerful validation, but introduces heavy external dependency not needed
  for a read-only audit mini project.
"""

from dataclasses import dataclass, field, asdict
from typing import Any, Dict


@dataclass
class Finding:
    """
    Standard Finding object produced by all CloudGuard scanners.
    
    Attributes:
        id: Unique identifier for this finding instance (e.g., 's3-public-bucket-cloudguard-demo').
        check_name: Human-readable name of the security check performed.
        resource_type: AWS resource type (e.g., 'AWS::S3::Bucket', 'AWS::IAM::User').
        resource_id: AWS resource name, ARN, or ID (e.g., 'cloudguard-test-public-bucket').
        region: AWS region where the resource resides ('ap-south-1' or 'global').
        severity: Inherent flaw severity ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL').
        exposure: Network/accessibility level ('PUBLIC' or 'INTERNAL').
        sensitivity: Data/business criticality of the asset ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL').
        evidence: Exact raw data from AWS API proving the misconfiguration.
        cis_id: CIS AWS Foundations Benchmark control ID (e.g., 'CIS-2.1.1'), or 'N/A'.
        remediation: Actionable guidance including exact AWS CLI command or Terraform fix.
        risk_score: Calculated numeric risk score (computed by scoring.py, default 0.0).
        resource: Combined 'type::identifier' string for easy reporting and grouping.
    """
    id: str
    check_name: str
    resource_type: str
    resource_id: str
    region: str
    severity: str
    exposure: str
    sensitivity: str
    evidence: Dict[str, Any]
    cis_id: str = "N/A"
    remediation: str = ""
    risk_score: float = 0.0
    resource: str = ""

    def __post_init__(self):
        """Ensure standard formatting and defaults."""
        if not self.resource:
            self.resource = f"{self.resource_type}::{self.resource_id}"
        
        # Normalize uppercase for consistency across scanners
        self.severity = self.severity.upper()
        self.exposure = self.exposure.upper()
        self.sensitivity = self.sensitivity.upper()

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to standard dictionary for JSON dumping and reporting."""
        return asdict(self)
