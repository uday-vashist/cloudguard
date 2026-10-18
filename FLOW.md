# CloudGuard End-to-End Execution Flow (FLOW.md)

This document traces the exact step-by-step execution of CloudGuard, explaining how data flows through every file and module. It is structured to help you clearly answer viva questions on program execution and data pipelining.

---

## 1. High-Level Execution Pipeline

When an auditor runs:
```powershell
python -m cloudguard.main --profile cloudguard --region ap-south-1
```

The system executes the following 6-step lifecycle:

```
[1. main.py] CLI Initialization & Session Startup
       │
       ▼
[2. aws_session.py] Wrap boto3 clients in ReadOnlyClientWrapper (Safety Guard)
       │
       ▼
[3. scanners/*.py] Execute S3, IAM, SG, and Monitoring audits
       │  Emits List[Finding]
       ▼
[4. cis_mapping.py] Tag findings with CIS AWS Foundations Benchmark Control IDs
       │
       ▼
[5. scoring.py] Calculate Risk Score (Severity x Exposure x Sensitivity) & Sort
       │  Emits List[Finding] ranked by risk_score desc
       ▼
[6. report.py] Render Jinja2 HTML Audit Report with Evidence & Remediation
       │
       ▼
[Output] reports/audit_report.html
```

---

## 2. Per-File Data Flow Breakdown

### A. `cloudguard/main.py`
- **What it receives**: CLI arguments (`--profile`, `--region`, `--smoke-test`, `--output`).
- **What it does**: 
  1. Parses arguments using Python `argparse`.
  2. Initializes the `CloudGuardSession` from `aws_session.py`.
  3. Dispatches calls to each audit scanner.
  4. Collects all `Finding` objects into a single list.
  5. Passes findings to `cis_mapping.py`, then `scoring.py`, and finally `report.py`.
- **What it returns**: Process exit status code (`0` on success, `1` on error).
- **Next file**: Passes session to `aws_session.py` and scanners; passes findings list to `cis_mapping.py`.

---

### B. `cloudguard/aws_session.py`
- **What it receives**: Profile name (`cloudguard`) and Region (`ap-south-1`).
- **What it does**:
  1. Creates an isolated `boto3.Session`.
  2. Intercepts client creation requests (`session.client("s3")`).
  3. Wraps the client in `ReadOnlyClientWrapper` using Python's `__getattr__` hook.
  4. Inspects every attempted method call. If the method does not start with `get_`, `list_`, or `describe_`, raises `ReadOnlyViolationError` and halts before any network request is sent.
- **What it returns**: A guarded `ReadOnlyClientWrapper` proxy instance.
- **Next file**: Handed to scanner modules in `cloudguard/scanners/`.

---

### C. `cloudguard/scanners/` (S3, IAM, Security Groups, Monitoring)
- **What it receives**: Guarded `ReadOnlyClientWrapper` for respective AWS services.
- **What it does**:
  1. Calls read-only AWS APIs (e.g., `list_buckets()`, `describe_security_groups()`).
  2. Evaluates configuration responses against defined security benchmarks.
  3. Extracts raw AWS JSON data as cryptographic/audit proof (`evidence`).
  4. Instantiates `Finding` objects defined in `cloudguard/models.py`.
- **What it returns**: `List[Finding]` containing all detected security misconfigurations.
- **Next file**: Hands list of `Finding` objects back to `main.py` (which forwards to `cis_mapping.py`).

---

### D. `cloudguard/cis_mapping.py`
- **What it receives**: `List[Finding]` emitted by scanners.
- **What it does**:
  1. Looks up each check name or finding type in the verified CIS AWS Foundations Benchmark dictionary.
  2. Injects the relevant `cis_id` (e.g., `CIS-2.1.1` for public S3, `CIS-5.2` for SSH SG exposure) into the `Finding.cis_id` attribute.
- **What it returns**: `List[Finding]` with compliance control tags populated.
- **Next file**: Hands tagged findings to `cloudguard/scoring.py`.

---

### E. `cloudguard/scoring.py`
- **What it receives**: `List[Finding]` with `cis_id` populated.
- **What it does**:
  1. Evaluates each finding's `severity`, `exposure`, and `sensitivity`.
  2. Calculates:
     $$\text{risk\_score} = \text{Severity Weight} \times \text{Exposure Multiplier} \times \text{Sensitivity Multiplier}$$
  3. Injects the numeric score into `Finding.risk_score`.
  4. Sorts all findings in descending order of `risk_score` so the highest threats appear first.
- **What it returns**: Sorted `List[Finding]` ranked by risk score.
- **Next file**: Hands ranked findings to `cloudguard/report.py`.

---

### F. `cloudguard/report.py`
- **What it receives**: Ranked `List[Finding]` and output filepath (`reports/audit_report.html`).
- **What it does**:
  1. Computes summary metrics: Total Findings, Critical/High/Medium/Low counts, Highest Risk Score.
  2. Loads the Jinja2 HTML template.
  3. Formats evidence JSON blocks and remediation commands (AWS CLI and Terraform snippets).
  4. Writes the self-contained HTML report to disk.
- **What it returns**: Filepath string of the generated HTML report.
- **Next file**: Writes report to `reports/audit_report.html` for browser viewing.

---

## 3. Worked Example: Tracing a Single Finding End-to-End

Let us trace a real-world misconfiguration: **An S3 bucket with public read access granted via bucket policy**.

### Step 1: Raw AWS API Response (boto3)
The scanner calls `s3_client.get_bucket_policy_status(Bucket="cloudguard-test-public-bucket")`.
AWS returns:
```json
{
  "PolicyStatus": {
    "IsPublic": true
  },
  "ResponseMetadata": {
    "HTTPStatusCode": 200
  }
}
```

### Step 2: Scanner Detection & Finding Instantiation (`s3_scanner.py`)
The scanner detects `IsPublic == True`. It constructs a `Finding` object:
```python
Finding(
    id="s3-public-policy-cloudguard-test-public-bucket",
    check_name="S3 Bucket Public Access via Policy",
    resource_type="AWS::S3::Bucket",
    resource_id="cloudguard-test-public-bucket",
    region="ap-south-1",
    severity="CRITICAL",
    exposure="PUBLIC",
    sensitivity="HIGH",
    evidence={"PolicyStatus": {"IsPublic": True}},
    remediation=(
        "aws s3api put-public-access-block --bucket cloudguard-test-public-bucket "
        "--public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,"
        "BlockPublicPolicy=true,RestrictPublicBuckets=true"
    )
)
```

### Step 3: CIS Compliance Tagging (`cis_mapping.py`)
`cis_mapping.py` matches `"S3 Bucket Public Access via Policy"` to CIS AWS Foundations Benchmark Control:
- Result: `finding.cis_id = "CIS-2.1.1"`

### Step 4: Risk Scoring Calculation (`scoring.py`)
`scoring.py` maps the qualitative attributes to mathematical weights:
- `Severity = "CRITICAL"` $\rightarrow 10.0$
- `Exposure = "PUBLIC"` $\rightarrow 2.0$
- `Sensitivity = "HIGH"` $\rightarrow 2.0$

$$\text{risk\_score} = 10.0 \times 2.0 \times 2.0 = \mathbf{40.0}$$
`finding.risk_score = 40.0`.
Because $40.0$ is among the highest scores, this finding is sorted to the very top of the list.

### Step 5: HTML Report Rendering (`report.py`)
`report.py` renders a row in the HTML report table:
- **Badge**: `CRITICAL` (Dark red badge)
- **Resource**: `AWS::S3::Bucket::cloudguard-test-public-bucket`
- **CIS Control**: `CIS-2.1.1`
- **Risk Score**: `40.0`
- **Collapsible Evidence**: Raw JSON `{"PolicyStatus": {"IsPublic": true}}`
- **Remediation Box**: Copyable AWS CLI command to block public access immediately.

---

## 4. Current Stage Status

- **Stage 1 (Completed)**:
  - Skeleton initialized (`cloudguard/`, `tests/`, `reports/`).
  - Read-only proxy safety guard implemented and verified (`cloudguard/aws_session.py`).
  - Core data model created (`cloudguard/models.py`).
  - STS smoke test active (`python -m cloudguard.main --smoke-test` and `tests/smoke_test.py`).
  - Architecture and Flow documents drafted.
- **Stage 2 (Completed)**:
  - Terraform testbed designed (`terraform/`) containing 100% Free-Tier safe misconfigurations:
    - S3: Public policy, BPA disabled with public ACL, missing encryption, plus compliant baseline.
    - IAM: Wildcard `*:*` admin user, user without MFA, active access key, overprivileged role, plus compliant scoped role.
    - Security Groups: Ingress `0.0.0.0/0` on port 22 (SSH), port 3389 (RDP), port 3306/5432 (DB), plus compliant HTTPS SG.
    - Monitoring: Single-region CloudTrail with log validation disabled.
  - Ground truth specification created (`tests/expected_findings.json`) with 14 documented benchmark misconfigurations.
- **Stage 3 (Completed)**:
  - S3 Scanner (`cloudguard/scanners/s3_scanner.py`):
    - Audits bucket policies (wildcard `Principal: "*"` on `s3:GetObject`).
    - Audits Block Public Access configuration (identifies disabled BPA settings).
    - Audits bucket ACLs (detects grants to `AllUsers` or `AuthenticatedUsers`).
    - Audits Server-Side Encryption (detects missing default SSE configuration).
    - Verified against compliant baselines to guarantee zero false positives.
  - IAM Scanner (`cloudguard/scanners/iam_scanner.py`):
    - Audits inline and attached policies for wildcard administrative rights (`Action:*`, `Resource:*`).
    - Audits IAM users without registered Multi-Factor Authentication (MFA).
    - Audits active and aged access keys requiring lifecycle rotation.
    - Audits IAM roles with direct `AdministratorAccess` attachment.
    - Verified against scoped least-privilege roles to guarantee zero false positives.
  - Unit test suite (`tests/test_stage3_scanners.py`) providing 100% offline verification.
- **Stage 4 (Completed)**:
  - Security Group Scanner (`cloudguard/scanners/sg_scanner.py`):
    - Audits ingress rules for unrestricted access (`0.0.0.0/0` and `::/0`).
    - Flags administrative ports: SSH (22) and RDP (3389) as CRITICAL.
    - Flags database ports: MySQL (3306), PostgreSQL (5432), MSSQL (1433), MongoDB (27017), Redis (6379), Oracle DB (1521) as CRITICAL.
    - Verified negative baselines (HTTPS 443 only and internal 10.0.0.0/16 rules generate zero false alarms).
  - Monitoring Scanner (`cloudguard/scanners/monitoring_scanner.py`):
    - Audits CloudTrail for multi-region logging (`IsMultiRegionTrail = True`).
    - Audits CloudTrail for cryptographic log file validation (`LogFileValidationEnabled = True`).
    - Audits CloudWatch for essential security alarms (root usage, unauthorized API calls).
    - Detects complete absence of logging trails as CRITICAL.
  - Unit test suite (`tests/test_stage4_scanners.py`) providing 100% offline verification (8 test cases).
- **Stage 5 (Completed)**:
  - Risk Scoring Engine (`cloudguard/scoring.py`):
    - Implemented documented 3-factor multiplicative formula:
      $$\text{Risk Score} = \text{Severity Weight} \times \text{Exposure Multiplier} \times \text{Resource Sensitivity Multiplier}$$
    - Factor weights: Severity (CRITICAL=10, HIGH=7, MEDIUM=4, LOW=1), Exposure (PUBLIC=2.0, INTERNAL=1.0), Sensitivity (CRITICAL=2.5, HIGH=2.0, MEDIUM=1.5, LOW=1.0).
    - Dynamic range from 1.0 to 50.0 providing 50x risk separation.
    - Implemented `score_and_rank_findings` sorting highest risk items first.
  - CIS Benchmark Mapping (`cloudguard/cis_mapping.py`):
    - Mapped all 14 implemented checks strictly to official CIS AWS Foundations Benchmark control IDs (CIS 1.5, 1.14, 1.16, 2.1.1, 2.1.2, 2.1.3, 3.1, 3.2, 3.4, 5.2, 5.3, 5.4).
    - Integrated rich control metadata (section, title, description) for reporting.
  - Unit test suite (`tests/test_stage5_scoring_cis.py`) with 4 test cases verifying formula precision, sorting, and control tagging.
- **Stage 6 (Completed)**:
  - HTML Report Generator (`cloudguard/report.py`): Standalone interactive HTML report with Jinja2, executive statistics, risk breakdown, raw evidence, and copyable AWS CLI / Terraform remediation commands.
  - Interactive client-side filtering (by severity: CRITICAL, HIGH, MEDIUM, LOW) and instantaneous keyword search.
  - Unit test suite (`tests/test_stage6_report.py`) with 10 test cases verifying XSS escaping, clean audit rendering, and metric integrity.
- **Stage 7 (Completed)**:
  - Validation script (`tests/validate.py`) computing precision and recall against `tests/expected_findings.json` (achieving 100% Precision and 100% Recall across all 14 ground truth items).
  - Offline Demonstration Mode: Added `--demo` flag to `cloudguard.main` allowing immediate full-pipeline execution, scoring, and HTML report generation without requiring live AWS account verification or credentials.
  - Comprehensive documentation and architectural guides (`ARCHITECTURE.md`, `FLOW.md`, `README.md`, `IAM_PERMISSIONS_REVIEW.md`).
