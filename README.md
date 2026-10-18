# CloudGuard - AWS Security Auditor & Risk Prioritization Engine

CloudGuard is a lightweight, read-only Cloud Security Posture Management (CSPM) tool implemented in Python (`boto3`) and Jinja2. It audits AWS account configurations across storage, identity, networking, and logging, prioritizes misconfigurations using a transparent mathematical risk-scoring formula, maps findings to the CIS AWS Foundations Benchmark, and renders an executive, self-contained HTML report.

CloudGuard includes code-level read-only safeguards and an offline verification testbed that validates scanner behavior without requiring live AWS credentials, cloud infrastructure, or internet access. The `tests/smoke_test.py::test_aws_sts_connectivity` test is included in the full pytest suite and may contact AWS STS when valid AWS credentials are configured.
---

## 1. Key Features & Audit Coverage

CloudGuard implements four specialized audit scanners adhering strictly to read-only AWS APIs:

| Domain | Scanner Module | Inspected Security Checks | CIS Benchmark |
| :--- | :--- | :--- | :--- |
| **Storage** | [`cloudguard/scanners/s3_scanner.py`](cloudguard/scanners/s3_scanner.py) | • S3 Bucket Public Access via Policy (`Principal: *`)<br>• Incomplete S3 Block Public Access settings<br>• Public Bucket ACLs (`AllUsers` / `AuthenticatedUsers`)<br>• Explicit default encryption status as an informational observation only | CIS-2.1.1<br>CIS-2.1.2<br>CIS-2.1.2 |
| **Identity** | [`cloudguard/scanners/iam_scanner.py`](cloudguard/scanners/iam_scanner.py) | • Wildcard Administrative Privileges (`*:*` in user policies)<br>• Verified console users without MFA<br>• Active access keys older than 90 days (90 days is within policy)<br>• Overprivileged IAM Roles (`AdministratorAccess`) | CIS-1.16<br>CIS-1.5<br>CIS-1.14<br>CIS-1.16 |
| **Network** | [`cloudguard/scanners/sg_scanner.py`](cloudguard/scanners/sg_scanner.py) | • Public ingress (`0.0.0.0/0` / `::/0`) on SSH (TCP 22)<br>• Public ingress on RDP (TCP 3389)<br>• Public ingress on database ports (MySQL 3306, PostgreSQL 5432, MSSQL 1433, MongoDB 27017, Redis 6379, Oracle 1521) | CIS-5.2<br>CIS-5.3<br>CIS-5.4 |
| **Logging** | [`cloudguard/scanners/monitoring_scanner.py`](cloudguard/scanners/monitoring_scanner.py) | • CloudTrail multi-region coverage and log validation<br>• CloudWatch security alarm candidates; configuration is explicitly unverified<br>• Empty regional CloudTrail results are not treated as account-wide absence | CIS-3.1<br>CIS-3.2<br>CIS-3.4 |

---

## 2. Risk Prioritization & Compliance Mapping

### 3-Factor Multiplicative Risk Formula
Traditional severity rankings (Low/Medium/High/Critical) fail to differentiate between an isolated test asset and an internet-exposed production database. CloudGuard calculates a numeric risk score ($0.0 - 50.0$) using a 3-factor multiplicative formula:

$$\text{Risk Score} = \text{Severity Weight} \times \text{Exposure Multiplier} \times \text{Resource Sensitivity Multiplier}$$

- **Severity Weight (Inherent technical flaw):**
  - `CRITICAL` (10.0): Wildcard `*:*` admin rights, open SSH/DB, public bucket policy.
  - `HIGH` (7.0): Disabled S3 BPA or single-region CloudTrail when no multi-region trail is present.
  - `MEDIUM` (4.0): User without MFA, disabled log validation, missing alarms.
  - `LOW` (1.0): Low-severity confirmed security issue.
  - `INFO` (0.0): Unverified status or observation; contributes no risk.
- **Exposure Multiplier (Attack reachability):**
  - `PUBLIC` (2.0): Directly reachable from `0.0.0.0/0` or open internet policy.
  - `INTERNAL` (1.0): Contained inside VPC private subnets or internal account boundaries.
- **Resource Sensitivity Multiplier (Asset criticality):**
  - `CRITICAL` (2.5): Root account, IAM admin roles, production database ports.
  - `HIGH` (2.0): S3 customer data buckets, core security groups, audit trails.
  - `MEDIUM` (1.5): Standard application workloads and operational tooling.
  - `LOW` (1.0): Non-sensitive, internal baseline assets.

*Multiplicative Advantage:* Confirmed findings range up to $50.0$; INFO observations are zero-score and excluded from aggregate risk.

The **aggregate risk** shown in the CLI and report is the sum of individual finding scores. Informational observations score zero and are shown separately from confirmed risk. Unknown scoring labels are rejected instead of silently assigned a default score.

### CIS AWS Foundations Benchmark Control Mapping
Every finding is enriched by [`cloudguard/cis_mapping.py`](cloudguard/cis_mapping.py) with official CIS control identifiers and descriptive metadata (title, section, description), allowing audit findings to serve directly as compliance evidence.

---

## 3. Interactive HTML Audit Report

CloudGuard renders a self-contained HTML report ([`cloudguard/report.py`](cloudguard/report.py)) saved by default to `reports/audit_report.html`:
- **Air-Gapped & Self-Contained:** Built with embedded CSS and Vanilla JS. Requires zero external CDN requests, font downloads, or internet connectivity to view.
- **Executive Summary:** Metric cards displaying confirmed findings, INFO observations, peak score, and aggregate risk.
- **Live Filtering & Search:** Client-side severity filtering and instant free-text search across resources and check titles.
- **Evidence handling:** Dynamic HTML is escaped, and secret-like evidence fields are redacted before rendering.
- **Collapsible Audit Evidence:** Expandable details blocks revealing the raw JSON API proof from AWS.
- **Remediation Guidance:** Suggested, copyable AWS CLI commands for addressing findings. Review each command and its potential impact before executing it; remediation commands may modify AWS resources.
- **Partial Audit Safety Warning:** If one or more scanners encounter an error during an audit, the report visibly renders a prominent warning banner listing the failed scanners, alerting users that the audit is incomplete.
- **Misleading Clean Report Guard:** If scanners fail and zero findings are gathered, report generation is deliberately skipped to prevent issuing a false clean-bill-of-health report.

---

## 4. Read-Only Safety Model

CloudGuard uses code-level safeguards to reduce the risk of accidental modification or deletion of AWS resources:

1. **Client Proxy Wrapper ([`cloudguard/aws_session.py`](cloudguard/aws_session.py)):** Boto3 clients are wrapped by `ReadOnlyClientWrapper`.
2. **Operation Allowlist:** The wrapper permits method names beginning with `get_`, `list_`, or `describe_`, along with approved utility methods such as `get_paginator`.
3. **Blocked Operations:** Calls that do not meet the allowlist rules raise a `ReadOnlyViolationError` at the wrapper level.
4. **Defense in Depth:** This wrapper is a code-level safeguard, not a complete security boundary. Configure AWS IAM permissions to independently restrict the audit identity to the read operations CloudGuard requires. Do not rely on the wrapper alone to enforce read-only access.

---

## 5. Quickstart & Installation (Windows PowerShell)

### Prerequisites
- Python 3.10+ (tested on Python 3.14.5).
- Windows PowerShell (or Command Prompt / bash).

### 1. Setup Virtual Environment
```powershell
# Navigate to project root
cd cloudguard

# Create virtual environment
python -m venv .venv

# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

### 2. Run Automated Tests

Run the offline automated suite. The separate `tests/smoke_test.py` module contains an explicit STS connectivity check and is excluded here to guarantee that this command makes no AWS calls:
```powershell
.\.venv\Scripts\python.exe -m pytest -v --ignore=tests/smoke_test.py
```

---

## 6. CLI Reference & Usage

CloudGuard provides an intuitive CLI via [`cloudguard/main.py`](cloudguard/main.py):

```powershell
python -m cloudguard.main [OPTIONS]
```

### Supported Arguments & Defaults

| Argument | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--demo` | flag | `False` | Run audit in offline demonstration mode using synthetic testbed (no AWS credentials or verification required) |
| `--profile` | `str` | `"cloudguard"` | Named AWS CLI profile in `~/.aws/credentials` |
| `--region` | `str` | `"ap-south-1"` | AWS region to audit |
| `--smoke-test` | flag | `False` | Verifies STS `get_caller_identity` and read-only session setup |
| `--output` | `str` | `"reports/audit_report.html"` | Filepath for the generated HTML report |

### Example Commands

#### A. Run Offline Audit Demo (No AWS Credentials or Verification Required)
Executes all four scanners against the mock testbed, scores findings, tags CIS controls, and generates HTML report:
```powershell
.\.venv\Scripts\python.exe -m cloudguard.main --demo
```

#### B. Run Smoke Test (Verify Authentication)
Validates STS identity without running scanners (use `--demo` for simulated check):
```powershell
.\.venv\Scripts\python.exe -m cloudguard.main --smoke-test --demo
# Or against live AWS:
.\.venv\Scripts\python.exe -m cloudguard.main --smoke-test --profile cloudguard --region ap-south-1
```

#### C. Run Live AWS Security Audit
Executes all four scanners against an authorized live AWS account:
```powershell
.\.venv\Scripts\python.exe -m cloudguard.main --profile my-profile --region ap-south-1 --output reports/audit_report.html
```

#### Exit Codes
- `0`: Successful execution (or clean audit).
- `1`: Error encountered, missing profile/credentials, or incomplete audit due to scanner failures.

---

## 7. Offline Detection Accuracy Validation

CloudGuard includes a dedicated ground-truth validation engine ([`tests/validate.py`](tests/validate.py)) that measures scanner precision and recall without making live AWS calls.

### Running the Validator
```powershell
.\.venv\Scripts\python.exe tests/validate.py
```

### Automated Validation Tests
```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_validate.py -v
```

### Output Summary
```text
==========================================================================
 CloudGuard - Offline Detection Accuracy & Ground Truth Validation
 (Synthetic Mock Environment - No live AWS calls or credentials used)
==========================================================================
 Ground Truth Source : tests/expected_findings.json
 Total Expected Items: 11
 Total Scanned Items : 11
--------------------------------------------------------------------------
 OVERALL DETECTION METRICS
--------------------------------------------------------------------------
 True Positives  (TP) : 11
 False Positives (FP) : 0
 False Negatives (FN) : 0
 Precision            : 100.0%
 Recall               : 100.0%

 Note: Convention defines 0.0% when the denominator (TP+FP or TP+FN)
 is zero to represent an undefined rate without division by zero.
--------------------------------------------------------------------------
 PER-CATEGORY BREAKDOWN
--------------------------------------------------------------------------
 Category         Expected   Actual    TP    FP    FN  Precision   Recall
 ---------------- -------- -------- ----- ----- ----- ---------- --------
 S3                      2        2     2     0     0     100.0%   100.0%
 IAM                     3        3     3     0     0     100.0%   100.0%
 SECURITY_GROUP          4        4     4     0     0     100.0%   100.0%
 MONITORING              2        2     2     0     0     100.0%   100.0%
==========================================================================
```

### Understanding the Validation Metrics
- **Ground Truth ([`tests/expected_findings.json`](tests/expected_findings.json)):** Manifest of 11 confirmed misconfigurations across S3, IAM, Security Groups, and Monitoring. Compliant keys, unverified S3 object encryption, and redundant single-region trails are not counted as vulnerabilities.
- **Synthetic Mock Environment:** Synthetic boto3 client mocks mirroring the 11 confirmed misconfigurations and compliant baseline resources. INFO observations are excluded from precision/recall.
- **Bijective 1-to-1 Matching:** An actual finding matches an expected item only once. Security group checks require exact exposed port matches (22, 3389, 3306, 5432), preventing findings with identical CIS IDs (e.g. `CIS-5.4`) from falsely matching different ports.
- **Metrics:**
  - $\text{True Positives (TP)}$: Planted misconfigurations correctly detected.
  - $\text{False Positives (FP)}$: Compliant baselines incorrectly flagged as violations.
  - $\text{False Negatives (FN)}$: Planted misconfigurations missed by the scanner.
  - $\text{Precision} = \frac{\text{TP}}{\text{TP} + \text{FP}}$ (Measures false-alarm resistance).
  - $\text{Recall} = \frac{\text{TP}}{\text{TP} + \text{FN}}$ (Measures detection completeness).
- **Zero-Denominator Convention:** If $(\text{TP} + \text{FP}) = 0$ or $(\text{TP} + \text{FN}) = 0$, the metric evaluates to `0.0%` rather than dividing by zero.

---

## 8. Offline Mock Testing vs. Live AWS Audit

It is important to distinguish between CloudGuard's offline validation and a live AWS audit.

| Aspect | Offline Validation (`tests/validate.py`) | Live AWS Audit (`cloudguard/main.py`) |
| :--- | :--- | :--- |
| **AWS Credentials** | Not required; uses mocked AWS responses | Requires appropriately configured AWS credentials |
| **Network Access** | Uses synthetic in-memory responses without AWS API calls | Requires network access to the relevant AWS endpoints |
| **Target Infrastructure** | Synthetic mock environment | Resources in the authorized AWS account |
| **Cloud Costs** | No AWS infrastructure or API usage required by the validator | Costs are not guaranteed to be zero; check applicable AWS pricing |
| **Verification Scope** | Tests scanner behavior, scoring, and matching against synthetic cases | Evaluates the security posture visible to the configured IAM identity |

The offline validator currently reports 11 true positives, zero false positives, and zero false negatives against its synthetic test cases. These results demonstrate matching performance in the mock environment and do not establish detection accuracy against real AWS accounts.

### Planned Next Step: Live AWS Account Audit

A live AWS audit is a separate step and has not been performed as part of the offline tests described above.

Before conducting a live audit:

1. **Authorization:** Obtain explicit permission to audit the target AWS account.
2. **Least-privilege access:** Use a dedicated IAM role or identity with only the read permissions required by the scanners. Review the required permissions before configuring access.
3. **Credential configuration:** If a live audit is authorized, configure a dedicated AWS CLI profile using an approved authentication method. Never commit credentials to the repository or share access keys in source code.
4. **Smoke test:** Verify account access before attempting a full audit:
   ```powershell
   python -m cloudguard.main --smoke-test --profile cloudguard
   ```
5. **Review results:** Check the report and any scanner failures before interpreting the results as a complete audit.

**Terraform warning:** The `terraform/` directory contains intentionally vulnerable test resources for testing purposes. These resources may expose services or permissions if deployed. Do not deploy them to an AWS account until the configuration, security implications, expected costs, and cleanup procedure have been reviewed and explicitly approved.

CloudGuard is designed to provide read-only auditing and does not automatically apply remediation changes.

---

## 9. Project Limitations

1. **Static Snapshot Audit:** CloudGuard evaluates resource state at the specific moment of invocation. It does not perform continuous event listening (e.g., EventBridge / GuardDuty streams).
2. **Single-Region Primary Focus:** Network and storage resources are scanned for the configured `--region` (`ap-south-1` by default), while IAM and CloudTrail multi-region checks evaluate global account posture.
3. **Client-Side HTML Viewing:** The generated report is designed for browser viewing and lacks an integrated server-side database.
4. **Remediation Commands:** The report provides copyable AWS CLI remediation commands, but CloudGuard does not automatically apply remediations in order to uphold its strict read-only guarantee.

---

## 10. Repository File Structure

```text
cloudguard/
├── cloudguard/                     # Core Package
│   ├── scanners/                   # Domain Audit Scanners
│   │   ├── s3_scanner.py           # S3 bucket policies, BPA, ACLs, SSE
│   │   ├── iam_scanner.py          # Wildcard policies, MFA, keys, admin roles
│   │   ├── sg_scanner.py           # Open administrative & database ports
│   │   └── monitoring_scanner.py   # Multi-region CloudTrail & CloudWatch alarms
│   ├── aws_session.py              # ReadOnlyClientWrapper proxy & boto3 session
│   ├── cis_mapping.py              # CIS AWS Foundations Benchmark metadata
│   ├── models.py                   # Standard Finding dataclass
│   ├── report.py                   # Jinja2 self-contained HTML report generator
│   ├── scoring.py                  # 3-factor multiplicative risk formula
│   └── main.py                     # CLI orchestrator & smoke test entry point
├── terraform/                      # Intentionally vulnerable AWS testbed templates; review before deployment
├── tests/                          # Automated tests and offline validation
│   ├── expected_findings.json      # Confirmed ground truth manifest (11 cases)
│   ├── smoke_test.py               # Safety wrapper & STS smoke tests
│   ├── test_pipeline.py            # End-to-end CLI & pipeline tests
│   ├── test_stage3_scanners.py     # S3 and IAM scanner unit tests
│   ├── test_stage4_scanners.py     # SG and Monitoring scanner unit tests
│   ├── test_stage5_scoring_cis.py  # Scoring & CIS tagging unit tests
│   ├── test_stage6_report.py       # HTML report rendering & XSS tests
│   ├── test_validate.py            # Ground truth validation unit tests
│   └── validate.py                 # Offline detection accuracy validation tool
├── reports/                        # Default output directory for audit reports
├── requirements.txt                # boto3, botocore, jinja2, pytest
├── pytest.ini                      # Test runner configuration
├── ARCHITECTURE.md                 # Detailed architectural specifications
├── FLOW.md                         # End-to-end data flow and viva reference
└── README.md                       # Main project documentation
```
