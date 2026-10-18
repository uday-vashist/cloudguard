"""
CloudGuard Risk Prioritization & Scoring Engine.

Why this file exists:
In enterprise cloud environments, security auditors face 'alert fatigue' when presented
with hundreds of unranked findings. CloudGuard prioritizes issues using a documented,
mathematical risk formula that evaluates the compounded risk of each vulnerability.

Mathematical Formula:
    Risk Score = Severity Weight × Exposure Multiplier × Resource Sensitivity Multiplier

Factor Weights Justification:
1. Severity Weight (Inherent Technical Impact of the flaw):
   - CRITICAL (10.0): Complete compromise (wildcard *:* admin privilege, public DB/SSH, public S3 policy)
    - HIGH (7.0): Significant vulnerability (disabled S3 BPA, single-region CloudTrail without a multi-region alternative)
   - MEDIUM (4.0): Security hygiene gap (missing user MFA, log validation off, missing security alarms)
    - LOW (1.0): Low-severity confirmed security issue
    - INFO (0.0): Unverified status or observation; excluded from risk totals

2. Exposure Multiplier (Network Reachability / Attack Surface):
   - PUBLIC (2.0): Directly exposed to the entire internet (0.0.0.0/0, ::/0, or open internet bucket policy).
     Attacker requires zero internal presence to discover and target the asset.
   - INTERNAL (1.0): Contained inside VPC private subnets or internal account boundaries.
     Requires an attacker to already have initial internal foothold.

3. Resource Sensitivity Multiplier (Criticality of the Asset):
   - CRITICAL (2.5): Root account, core IAM admin roles, production databases hosting customer data.
   - HIGH (2.0): Customer data buckets, primary application security groups.
   - MEDIUM (1.5): Standard operational workloads and internal tooling.
   - LOW (1.0): Dev/test environments, scratch buckets, temporary roles.

Design Decisions & Alternatives Considered:
- Alternative 1 (Additive Scoring: Sev + Exp + Sens):
  Rejected because additive scoring compresses the dynamic range (e.g., 7 + 2 + 1 = 10 vs 4 + 2 + 2 = 8).
  Multiplicative scoring magnifies the compounding effect of an exposed critical asset
  (10 × 2.0 × 2.5 = 50.0 vs 1.0 × 1.0 × 1.0 = 1.0), yielding a clear 50x separation of urgency.
- Alternative 2 (CVSS v3.1):
  Popular for software CVEs, but overly complex for cloud configuration audits where parameters like
  'User Interaction' or 'Attack Complexity' do not cleanly apply to static IAM policies or security groups.
"""

from typing import List
from cloudguard.models import Finding

# Severity weights (base technical flaw severity)
SEVERITY_WEIGHTS = {
    "INFO": 0.0,
    "CRITICAL": 10.0,
    "HIGH": 7.0,
    "MEDIUM": 4.0,
    "LOW": 1.0,
}

# Exposure multipliers (reachability from internet)
EXPOSURE_MULTIPLIERS = {
    "PUBLIC": 2.0,
    "INTERNAL": 1.0,
}

# Sensitivity multipliers (business/data criticality of the asset)
SENSITIVITY_MULTIPLIERS = {
    "CRITICAL": 2.5,
    "HIGH": 2.0,
    "MEDIUM": 1.5,
    "LOW": 1.0,
}


def calculate_risk_score(severity: str, exposure: str, sensitivity: str) -> float:
    """
    Computes numeric risk score given severity, exposure, and sensitivity strings.
    Formula: Severity × Exposure × Sensitivity
    Returns float rounded to 1 decimal place.
    """
    severity_key = severity.upper()
    exposure_key = exposure.upper()
    sensitivity_key = sensitivity.upper()
    if severity_key not in SEVERITY_WEIGHTS:
        raise ValueError(f"Unsupported finding severity: {severity}")
    if exposure_key not in EXPOSURE_MULTIPLIERS:
        raise ValueError(f"Unsupported exposure level: {exposure}")
    if sensitivity_key not in SENSITIVITY_MULTIPLIERS:
        raise ValueError(f"Unsupported sensitivity level: {sensitivity}")

    sev_weight = SEVERITY_WEIGHTS[severity_key]
    exp_mult = EXPOSURE_MULTIPLIERS[exposure_key]
    sens_mult = SENSITIVITY_MULTIPLIERS[sensitivity_key]

    raw_score = sev_weight * exp_mult * sens_mult
    return round(raw_score, 1)


def score_and_rank_findings(findings: List[Finding]) -> List[Finding]:
    """
    Computes risk_score for every finding and returns a new list sorted
    in descending order of risk_score (highest threat first).
    """
    for finding in findings:
        finding.risk_score = calculate_risk_score(
            severity=finding.severity,
            exposure=finding.exposure,
            sensitivity=finding.sensitivity,
        )

    # Sort descending by risk_score; tie-break by check_name and id for deterministic output
    ranked = sorted(
        findings,
        key=lambda f: (f.risk_score, f.severity, f.check_name, f.id),
        reverse=True
    )
    return ranked


def aggregate_risk_score(findings: List[Finding]) -> float:
    """Return the sum of individual scores; INFO observations contribute zero."""
    return round(sum(finding.risk_score for finding in findings), 1)
