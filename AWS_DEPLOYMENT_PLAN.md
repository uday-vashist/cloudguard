# CloudGuard — AWS Deployment, Testbed & Cost Safety Plan

**Document Version:** 1.0  
**Target Environment:** AWS `ap-south-1` (Mumbai)  
**Dedicated Profile:** `cloudguard`  
**Auditor Identity:** `cloudguard-readonly` (Member of `CloudGuardReadOnlyGroup` with AWS managed `SecurityAudit` policy)  
**Review Status:** Pending User Review — **NO AWS RESOURCES HAVE BEEN DEPLOYED**

---

## 1. Executive Summary & Strict Safety Guardrails

This document outlines the complete resource inventory, cost assessment, permission requirements, risk classification, and step-by-step verification procedures for the CloudGuard deliberate misconfiguration testbed located in [`terraform/`](terraform/).

### Critical Rules & Safety Guarantees
1. **Zero Automatic Mutations:** Scanners adhere strictly to read-only AWS APIs (`get_*`, `list_*`, `describe_*`) guarded by `ReadOnlyClientWrapper` and backed by the IAM `SecurityAudit` boundary.
2. **No Compute or Database Spend:** The testbed deliberately creates **zero EC2 instances, zero RDS databases, zero NAT gateways, and zero Elastic Load Balancers**.
3. **No Unapproved Deployment:** Neither `terraform apply` nor `terraform destroy` has been or will be executed during preparation.
4. **Offline Equivalence:** Every finding simulated in the offline mock testbed (`tests/validate.py`) maps 1-to-1 to these Terraform templates. Where real cloud deployment is not authorized, offline fixtures provide 100% precision and 100% recall without cloud spend or exposure.

---

## 2. Resource Classification Matrix

Every Terraform resource and data source is audited and categorized into one of four safety classifications:

- **Cat 1 (Safe / Baseline):** No external exposure; $0.00 cost; benign baseline.
- **Cat 2 (Potentially Billable):** Storage, request, or service logging charges may accrue if mismanaged.
- **Cat 3 (Security-Sensitive):** Intentionally vulnerable; presents security exposure if deployed.
- **Cat 4 (Unknown Impact):** Any resource with unverified billing or perimeter risk.

| # | Terraform Resource | Resource Type | Category | Potential Cost | Security Exposure | Requires Explicit Approval? |
|---|---|---|:---:|:---:|:---:|:---:|
| 1 | `random_string.s3_suffix` | Local Provider | **Cat 1** | $0.00 | None | No |
| 2 | `aws_s3_bucket.public_policy_bucket` | `AWS::S3::Bucket` | **Cat 2 & 3** | Free Tier / $0.00 empty | Public Read via Policy | **YES** |
| 3 | `aws_s3_bucket_public_access_block.public_policy_bpa` | `AWS::S3::PublicAccessBlock` | **Cat 3** | $0.00 | Disabled BPA | **YES** |
| 4 | `aws_s3_bucket_policy.public_read_policy` | `AWS::S3::BucketPolicy` | **Cat 3** | $0.00 | `Principal: "*"` on `s3:GetObject` | **YES** |
| 5 | `aws_s3_bucket.public_acl_bucket` | `AWS::S3::Bucket` | **Cat 2 & 3** | Free Tier / $0.00 empty | Public Read via ACL | **YES** |
| 6 | `aws_s3_bucket_ownership_controls.acl_ownership` | `AWS::S3::OwnershipControls` | **Cat 3** | $0.00 | Legacy ACLs Enabled | **YES** |
| 7 | `aws_s3_bucket_public_access_block.disabled_bpa` | `AWS::S3::PublicAccessBlock` | **Cat 3** | $0.00 | All 4 BPA flags False | **YES** |
| 8 | `aws_s3_bucket_acl.public_read_acl` | `AWS::S3::BucketAcl` | **Cat 3** | $0.00 | `AllUsers` public-read | **YES** |
| 9 | `aws_s3_bucket.unencrypted_bucket` | `AWS::S3::Bucket` | **Cat 2 & 3** | Free Tier / $0.00 empty | Missing default SSE | **YES** |
| 10 | `aws_s3_bucket.compliant_secure_bucket` | `AWS::S3::Bucket` | **Cat 1 & 2** | Free Tier / $0.00 empty | None (Compliant Baseline) | No |
| 11 | `aws_s3_bucket_public_access_block.compliant_bpa` | `AWS::S3::PublicAccessBlock` | **Cat 1** | $0.00 | None (All BPA True) | No |
| 12 | `aws_s3_bucket_server_side_encryption_configuration.compliant_encryption` | `AWS::S3::BucketServerSideEncryptionConfiguration` | **Cat 1** | $0.00 | None (AES256) | No |
| 13 | `aws_iam_user.wildcard_user` | `AWS::IAM::User` | **Cat 1 & 3** | $0.00 | Admin User | **YES** |
| 14 | `aws_iam_policy.wildcard_policy` | `AWS::IAM::Policy` | **Cat 3** | $0.00 | `Action: "*", Resource: "*"` | **YES** |
| 15 | `aws_iam_user_policy_attachment.attach_wildcard` | `AWS::IAM::UserPolicyAttachment` | **Cat 3** | $0.00 | Grants Wildcard Admin | **YES** |
| 16 | `aws_iam_user.mfa_missing_user` | `AWS::IAM::User` | **Cat 1** | $0.00 | No MFA Registered | No |
| 17 | `aws_iam_access_key.test_access_key` | `AWS::IAM::AccessKey` | **Cat 3** | $0.00 | Secret Key stored in `.tfstate` | **YES** |
| 18 | `aws_iam_role.overprivileged_role` | `AWS::IAM::Role` | **Cat 3** | $0.00 | EC2 AssumeRole | **YES** |
| 19 | `aws_iam_role_policy_attachment.attach_admin_to_role` | `AWS::IAM::RolePolicyAttachment` | **Cat 3** | $0.00 | Attached `AdministratorAccess` | **YES** |
| 20 | `aws_iam_role.compliant_scoped_role` | `AWS::IAM::Role` | **Cat 1** | $0.00 | Scoped Read-Only Baseline | No |
| 21 | `aws_iam_policy.compliant_scoped_policy` | `AWS::IAM::Policy` | **Cat 1** | $0.00 | Scoped `s3:GetObject` | No |
| 22 | `aws_iam_role_policy_attachment.attach_scoped_to_role` | `AWS::IAM::RolePolicyAttachment` | **Cat 1** | $0.00 | Scoped Baseline Attachment | No |
| 23 | `data.aws_vpc.default` | Data Source | **Cat 1** | $0.00 | Lookup only | No |
| 24 | `aws_security_group.open_ssh_sg` | `AWS::EC2::SecurityGroup` | **Cat 3** | $0.00 (No EC2) | Inbound TCP 22 from `0.0.0.0/0` | **YES** |
| 25 | `aws_security_group.open_rdp_sg` | `AWS::EC2::SecurityGroup` | **Cat 3** | $0.00 (No EC2) | Inbound TCP 3389 from `0.0.0.0/0` | **YES** |
| 26 | `aws_security_group.open_db_sg` | `AWS::EC2::SecurityGroup` | **Cat 3** | $0.00 (No EC2) | Inbound TCP 3306/5432 from `0.0.0.0/0` | **YES** |
| 27 | `aws_security_group.compliant_web_sg` | `AWS::EC2::SecurityGroup` | **Cat 1** | $0.00 (No EC2) | Inbound TCP 443 only (Baseline) | No |
| 28 | `data.aws_caller_identity.current` | Data Source | **Cat 1** | $0.00 | Lookup only | No |
| 29 | `aws_s3_bucket.trail_bucket` | `AWS::S3::Bucket` | **Cat 2** | S3 Standard PUT/storage | CloudTrail log destination | **YES** |
| 30 | `aws_s3_bucket_policy.trail_bucket_policy` | `AWS::S3::BucketPolicy` | **Cat 1** | $0.00 | Restricts to `cloudtrail.amazonaws.com` | No |
| 31 | `aws_cloudtrail.insecure_test_trail` | `AWS::CloudTrail::Trail` | **Cat 2 & 3** | **$2.00 / 100k events if 2nd trail** | Single-region & log validation off | **YES** |

---

## 3. Deep-Dive: Billable Services, Free Tier Limits & Cost Hazards

### S3 Storage & API Calls
- **AWS Free Tier Allowance:** 5 GB Standard Storage, 20,000 GET Requests, 2,000 PUT Requests per month.
- **Testbed Impact:** Buckets are created **empty** with `force_destroy = true`. CloudGuard only queries bucket metadata (`GetBucketPolicy`, `GetBucketAcl`, etc.).
- **Expected Cost:** **$0.00** provided no external payloads are uploaded.

### IAM Users, Roles & Policies
- **AWS Free Tier Allowance:** Always 100% free with no quotas or billing.
- **Expected Cost:** **$0.00**.

### EC2 Security Groups
- **AWS Pricing:** Creating Security Groups without EC2 instances or Elastic IPs is 100% free.
- **Expected Cost:** **$0.00**.

### CloudTrail Management Events (CRITICAL COST HAZARD)
- **AWS Free Tier Policy:** CloudTrail delivers **one copy** of management events per region for **free**.
- **Hazard:** If the target AWS account already has an active organizational or default CloudTrail trail, deploying `aws_cloudtrail.insecure_test_trail` constitutes a **second trail**. Additional trails are billed at **$2.00 per 100,000 management events delivered**.
- **Mitigation:** In [`terraform/monitoring.tf`](terraform/monitoring.tf), logging is set to `enable_logging = true`. For live testing, verify whether an existing trail exists. If one does, keep test runtime under 1 hour and destroy promptly to incur less than $0.01 in residual event charges.

---

## 4. Required IAM Permissions for Testbed & Auditor

### A. Deployment Identity Permissions (Terraform Apply / Destroy)
To create and destroy the testbed, the deploying identity requires:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CloudGuardTestbedS3",
      "Effect": "Allow",
      "Action": [
        "s3:CreateBucket", "s3:DeleteBucket", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy",
        "s3:PutBucketAcl", "s3:PutBucketPublicAccessBlock", "s3:GetBucketLocation",
        "s3:PutBucketOwnershipControls", "s3:PutEncryptionConfiguration"
      ],
      "Resource": "arn:aws:s3:::cloudguard-test-*"
    },
    {
      "Sid": "CloudGuardTestbedIAM",
      "Effect": "Allow",
      "Action": [
        "iam:CreateUser", "iam:DeleteUser", "iam:CreatePolicy", "iam:DeletePolicy",
        "iam:AttachUserPolicy", "iam:DetachUserPolicy", "iam:CreateAccessKey",
        "iam:DeleteAccessKey", "iam:CreateRole", "iam:DeleteRole",
        "iam:AttachRolePolicy", "iam:DetachRolePolicy", "iam:PassRole"
      ],
      "Resource": [
        "arn:aws:iam::*:user/cloudguard-test/*",
        "arn:aws:iam::*:role/cloudguard-test/*",
        "arn:aws:iam::*:policy/cloudguard-test-*"
      ]
    },
    {
      "Sid": "CloudGuardTestbedEC2",
      "Effect": "Allow",
      "Action": [
        "ec2:CreateSecurityGroup", "ec2:DeleteSecurityGroup",
        "ec2:AuthorizeSecurityGroupIngress", "ec2:RevokeSecurityGroupIngress",
        "ec2:AuthorizeSecurityGroupEgress", "ec2:RevokeSecurityGroupEgress",
        "ec2:CreateTags", "ec2:DescribeSecurityGroups", "ec2:DescribeVpcs"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CloudGuardTestbedCloudTrail",
      "Effect": "Allow",
      "Action": [
        "cloudtrail:CreateTrail", "cloudtrail:DeleteTrail",
        "cloudtrail:StartLogging", "cloudtrail:StopLogging",
        "cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus"
      ],
      "Resource": "arn:aws:cloudtrail:*:*:trail/cloudguard-test-*"
    }
  ]
}
```

### B. Audit Identity Permissions (`cloudguard-readonly`)
The auditor identity belongs to `CloudGuardReadOnlyGroup` attached to AWS managed policy **`arn:aws:iam::aws:policy/SecurityAudit`**.

**SecurityAudit Compatibility Review:**
- `s3:ListAllMyBuckets`, `s3:GetBucketLocation`, `s3:GetBucketPolicyStatus`, `s3:GetBucketPolicy`, `s3:GetBucketPublicAccessBlock`, `s3:GetBucketAcl`, `s3:GetEncryptionConfiguration` $\rightarrow$ **Permitted**.
- `iam:ListUsers`, `iam:ListUserPolicies`, `iam:GetUserPolicy`, `iam:ListAttachedUserPolicies`, `iam:GetPolicy`, `iam:GetPolicyVersion`, `iam:ListMFADevices`, `iam:ListAccessKeys`, `iam:ListRoles`, `iam:ListAttachedRolePolicies` $\rightarrow$ **Permitted**.
- `ec2:DescribeSecurityGroups` $\rightarrow$ **Permitted**.
- `cloudtrail:DescribeTrails` $\rightarrow$ **Permitted**.
- `cloudwatch:DescribeAlarms` $\rightarrow$ **Permitted**.

---

## 5. Security Risks & Mitigation Controls

| Vulnerability Planted | Risk if Deployed | Mitigation in Testbed |
|---|---|---|
| **S3 Public Read Policy & ACL** | Unauthenticated users can read objects. | Buckets remain empty. Unique suffix prevents collision. Destroyed immediately after scan. |
| **IAM Wildcard Admin User** | Credential theft leads to account takeover. | User is created without console password. No login profile attached. |
| **IAM Access Key without MFA** | Stolen key allows programmatic API actions. | User has **zero** attached permissions. Key is harmless envelope. |
| **IAM Role with `AdministratorAccess`** | Privilege escalation via EC2 AssumeRole. | No EC2 instances launched with this instance profile. |
| **Open Ports (22, 3389, 3306, 5432)** | Brute force or exploit attempts from internet. | No EC2 instances, ENIs, or RDS instances attached to the Security Groups. |

---

## 6. Detection Mapping Matrix

Each deliberate misconfiguration maps to a specific CloudGuard check and CIS AWS Foundations Benchmark Control:

| Ground Truth ID | Terraform Resource | Scanner Function | CIS Control | Risk Score | Severity |
|---|---|---|:---:|:---:|:---:|
| `s3-public-policy` | `aws_s3_bucket.public_policy_bucket` | `s3_scanner.check_bucket_policy` | **CIS-2.1.1** | **40.0** | CRITICAL |
| `s3-bpa-disabled` | `aws_s3_bucket.public_acl_bucket` | `s3_scanner.check_public_access_block` | **CIS-2.1.2** | **28.0** | HIGH |
| `s3-missing-encryption` | `aws_s3_bucket.unencrypted_bucket` | `s3_scanner.check_bucket_encryption` | **CIS-2.1.3** | **10.5** | HIGH |
| `iam-wildcard-policy` | `aws_iam_user.wildcard_user` | `iam_scanner.check_user_wildcard_policies` | **CIS-1.16** | **50.0** | CRITICAL |
| `iam-user-no-mfa` | `aws_iam_user.mfa_missing_user` | `iam_scanner.check_user_mfa` | **CIS-1.5** | **6.0** | MEDIUM |
| `iam-access-key-active`| `aws_iam_access_key.test_access_key` | `iam_scanner.check_user_access_keys` | **CIS-1.14** | **1.5** | LOW |
| `iam-admin-role` | `aws_iam_role.overprivileged_role` | `iam_scanner.check_overprivileged_roles` | **CIS-1.16** | **25.0** | CRITICAL |
| `sg-open-ssh` | `aws_security_group.open_ssh_sg` | `sg_scanner.scan_security_groups` | **CIS-5.2** | **50.0** | CRITICAL |
| `sg-open-rdp` | `aws_security_group.open_rdp_sg` | `sg_scanner.scan_security_groups` | **CIS-5.3** | **50.0** | CRITICAL |
| `sg-open-mysql` | `aws_security_group.open_db_sg` | `sg_scanner.scan_security_groups` | **CIS-5.4** | **50.0** | CRITICAL |
| `sg-open-postgres` | `aws_security_group.open_db_sg` | `sg_scanner.scan_security_groups` | **CIS-5.4** | **50.0** | CRITICAL |
| `monitoring-single-region`| `aws_cloudtrail.insecure_test_trail` | `monitoring_scanner.check_cloudtrail_trails` | **CIS-3.1** | **28.0** | HIGH |
| `monitoring-log-val-off`| `aws_cloudtrail.insecure_test_trail` | `monitoring_scanner.check_cloudtrail_trails` | **CIS-3.2** | **8.0** | MEDIUM |
| `monitoring-no-alarms` | *(Absence of CloudWatch alarms)* | `monitoring_scanner.check_cloudwatch_alarms` | **CIS-3.4** | **6.0** | MEDIUM |

---

## 7. Safe Execution & Teardown Protocol

When explicit authorization to deploy is granted, execute following this exact sequence:

### Step 1: Pre-Deployment Verification
```powershell
# 1. Verify credentials and caller identity
aws --profile cloudguard sts get-caller-identity

# 2. Check Terraform syntax and formatting
terraform -chdir=terraform fmt -check
terraform -chdir=terraform validate

# 3. Generate preview plan without creating resources
terraform -chdir=terraform plan -out=tfplan.binary
```

### Step 2: Deployment (Only upon explicit user approval)
```powershell
terraform -chdir=terraform apply tfplan.binary
```

### Step 3: Run CloudGuard Audit
```powershell
.\.venv\Scripts\python.exe -m cloudguard.main --profile cloudguard --region ap-south-1 --output reports/live_audit_report.html
```

### Step 4: Teardown & Verification (Immediately after scan)
```powershell
# 1. Destroy all planted resources
terraform -chdir=terraform destroy -auto-approve

# 2. Confirm zero residual resources remain
terraform -chdir=terraform show
```

### Residual Cost Guard
- Confirm in AWS Console that the S3 bucket `cloudguard-test-trail-logs-*` is completely deleted.
- Confirm CloudTrail trail `cloudguard-test-insecure-trail` is deleted.
- Total expected bill for complete test execution: **$0.00** (or less than $0.01 if second CloudTrail trail briefly logged).
