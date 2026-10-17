# CloudGuard — IAM Permissions and Security Review

**Status:** Draft — pending team review  
**Purpose:** Centralize the scanner permission inventory, known limitations, read-only safety considerations, and remaining tasks before live AWS validation.

---

## 1. Purpose and Safety Principles

CloudGuard audits AWS configurations across storage, identity, networking, and monitoring. It identifies security misconfigurations, prioritizes findings, maps findings to CIS controls, and generates an HTML report.

The audit identity should have only the permissions required to perform these checks.

- CloudGuard is designed for read-only auditing.
- Remediation commands shown in findings are suggestions; scanners do not execute them.
- The application-level read-only wrapper is a safeguard, not a complete security boundary.
- AWS IAM permissions must independently restrict the audit identity.
- Do not use root credentials or broad administrative access for auditing.
- Review the intentionally vulnerable Terraform testbed before any deployment.
- Do not deploy resources or change AWS permissions without explicit team approval.

## 2. Combined Scanner Permission Inventory

The following actions were identified from the current scanner source code. This is a draft inventory, not yet a validated IAM policy.

### 2.1 S3 Scanner

| IAM action | Purpose |
|---|---|
| `s3:ListAllMyBuckets` | Discover buckets |
| `s3:GetBucketLocation` | Identify bucket regions |
| `s3:GetBucketPolicyStatus` | Check public bucket-policy status |
| `s3:GetBucketPolicy` | Read bucket policies |
| `s3:GetBucketPublicAccessBlock` | Inspect public-access-block settings |
| `s3:GetBucketAcl` | Inspect bucket ACL grants |
| `s3:GetEncryptionConfiguration` | Check default bucket encryption |

**Resource scope:** `s3:ListAllMyBuckets` requires `Resource: "*"`. Bucket-level operations should be scoped to relevant bucket ARNs wherever supported.

**Known limitation:** Some `AccessDenied` responses are ignored or treated as non-findings. This may cause incomplete checks to appear clean.

### 2.2 IAM Scanner

| IAM action | Purpose |
|---|---|
| `iam:ListUsers` | Discover IAM users |
| `iam:ListUserPolicies` | List inline user policies |
| `iam:GetUserPolicy` | Read inline user policy documents |
| `iam:ListAttachedUserPolicies` | Inspect policies attached to users |
| `iam:GetPolicy` | Read managed-policy metadata |
| `iam:GetPolicyVersion` | Read managed-policy documents |
| `iam:ListMFADevices` | Check registered MFA devices |
| `iam:ListAccessKeys` | Inspect access-key status and age |
| `iam:ListRoles` | Discover IAM roles |
| `iam:ListAttachedRolePolicies` | Inspect policies attached to roles |

**Resource scope:** List operations commonly require `Resource: "*"`. Verify resource-level support and conditions for each action before finalizing the policy.

**Known limitations:**

- Several `ClientError` exceptions are silently ignored.
- The scanner checks user policies for wildcard permissions and detects the AWS-managed `AdministratorAccess` policy on roles.
- It does not currently inspect role inline policies or customer-managed role policy documents for wildcard permissions.
- Its wildcard check looks for the exact combination of `Action: "*"` and `Resource: "*"`. Other potentially broad permission patterns may be missed.

### 2.3 EC2 Security Group Scanner

| IAM action | Purpose |
|---|---|
| `ec2:DescribeSecurityGroups` | Inspect inbound security group rules |

**Resource scope:** This Describe operation generally requires `Resource: "*"`.

**Known limitations:**

- The scanner focuses on selected administrative and database ports exposed to `0.0.0.0/0` or `::/0`.
- It does not represent a complete assessment of every possible network exposure.
- API failures are logged, but the scanner's error handling must be checked against the main pipeline's incomplete-audit reporting.

### 2.4 CloudTrail and CloudWatch Monitoring Scanner

| IAM action | Purpose |
|---|---|
| `cloudtrail:DescribeTrails` | Inspect configured trails |
| `cloudwatch:DescribeAlarms` | Inspect metric alarms |

**Resource scope:** These Describe operations generally require `Resource: "*"`.

**Known limitations:**

- API errors are logged, and the affected check returns no findings.
- The CloudWatch scanner identifies potential security alarms using keywords in alarm names and metric names. It does not prove that alarms are correctly configured or functioning.
- The scanner does not verify all possible CloudTrail settings or that every important security event has effective alarm coverage.

---

## 3. Main Pipeline Review

The current `cloudguard/main.py`:

1. Initializes a CloudGuard session.
2. Runs the S3, IAM, security group, and monitoring scanners.
3. Records uncaught scanner exceptions.
4. Generates a partial report when some scanners fail but other findings are available.
5. Skips report generation when scanner failures occur and no findings were gathered.
6. Returns a nonzero exit code when recorded scanner failures occur.

**Important limitation:** The pipeline can only report errors that propagate to it. If a scanner catches an AWS error internally and returns an empty or partial findings list, the pipeline may report that scanner as completed.

Therefore, a report containing zero findings does not automatically prove that the account is secure or that every check succeeded.

---

## 4. Read-Only Wrapper Review

The current `ReadOnlyClientWrapper` uses operation-name prefixes such as `get_`, `list_`, and `describe_` to permit selected calls.

Known limitations identified during code review:

- Some legitimate read-only operations, such as `head_bucket`, may be blocked.
- The paginator wrapper applies its own operation-name checks but is not an authorization boundary.
- Access to internal attributes such as `_raw_client` may bypass the wrapper.
- The wrapper does not replace AWS-side authorization.

**Required safeguard:** Restrict the audit identity through AWS IAM independently of the application wrapper. Review the wrapper implementation and test its behavior before live integration.

---

## 5. Validation Completed

Previous offline synthetic validation reported:

| Metric | Result |
|---|---:|
| Expected findings | 14 |
| Actual findings | 14 |
| True positives | 14 |
| False positives | 0 |
| False negatives | 0 |
| Precision | 100% |
| Recall | 100% |

These results apply only to the synthetic mocked test environment. They do not establish live AWS detection accuracy, complete permission coverage, or successful AWS authentication.

The automated test suite previously passed with the smoke test excluded.

**Smoke-test note:** `tests/smoke_test.py` and the CLI smoke-test mode can contact AWS STS when valid credentials are configured. A passing test that catches exceptions does not necessarily prove that AWS connectivity succeeded.

---

## 6. Remaining Work

- [ ] Review the permission inventory with the team.
- [ ] Inspect `cloudguard/aws_session.py` and verify client creation and wrapper behavior.
- [ ] Improve scanner error handling so skipped checks are reported as incomplete.
- [ ] Review role inline and customer-managed policy inspection coverage.
- [ ] Verify IAM action names and resource-scope requirements against current AWS documentation.
- [ ] Draft and review a least-privilege IAM policy without attaching it.
- [ ] Confirm the intended AWS account and approved audit environment.
- [ ] If live testing is approved, use a dedicated restricted audit identity.
- [ ] Review the Terraform testbed for intentionally vulnerable resources before any deployment.
- [ ] Compare live findings with known test conditions and document coverage gaps.
- [ ] Rerun automated tests after any code changes.

---

## 7. Current Project Status

At the time of this review:

- Scanner permission inventory has been drafted from source code.
- Known scanner and wrapper limitations have been recorded.
- Offline synthetic validation has been completed.
- The IAM policy has not been finalized or attached.
- No AWS resources have been deployed as part of this review.
- Live AWS validation remains pending.

**Next milestone:** Review the permissions and error-handling behavior with the team before attempting a live AWS audit.
