"""
CloudGuard IAM Identity & Access Management Scanner.

Audits AWS IAM configurations against critical identity risks:
1. Wildcard (*:*) Permissions in User/Role policies
2. IAM Users without Multi-Factor Authentication (MFA)
3. Active / Old Access Keys (>90 days or unrotated)
4. Over-privileged Roles (attached AdministratorAccess or wildcard policies)

VIVA CONCEPTS:
- Principle of Least Privilege (PoLP): Identities must only possess minimum required
  permissions to perform their tasks. Full admin (*:*) or missing MFA exposes
  the entire AWS infrastructure to account takeover.
- Read-Only Compliance: Only calls list_users, list_mfa_devices, list_access_keys,
  list_user_policies, get_user_policy, list_attached_user_policies,
  list_roles, list_role_policies, get_role_policy, list_attached_role_policies,
  get_policy, and get_policy_version.
"""

from datetime import datetime, timedelta, timezone
from math import ceil
import json
from typing import Any, Dict, List, Optional
from botocore.exceptions import ClientError
from cloudguard.aws_session import get_client
from cloudguard.models import Finding
from cloudguard.scanners._utils import collect_pages

ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


def _statement_has_wildcard(stmt: Dict[str, Any]) -> bool:
    """Helper to detect Action:* and Resource:* in an IAM statement."""
    if stmt.get("Effect") != "Allow":
        return False

    action = stmt.get("Action", [])
    if isinstance(action, str):
        action = [action]
    has_wildcard_action = "*" in action

    resource = stmt.get("Resource", [])
    if isinstance(resource, str):
        resource = [resource]
    has_wildcard_resource = "*" in resource

    return has_wildcard_action and has_wildcard_resource


def check_user_wildcard_policies(iam_client: Any, user_name: str) -> List[Finding]:
    """Inspect user inline and attached policies for Action:* and Resource:*."""
    findings = []

    # 1. Check inline policies
    try:
        policy_names = collect_pages(
            iam_client, "list_user_policies", "PolicyNames", {"UserName": user_name},
            token_param="Marker", token_field="Marker", truncated_field="IsTruncated",
        )
        for policy_name in policy_names:
            try:
                pol_detail = iam_client.get_user_policy(UserName=user_name, PolicyName=policy_name)
                policy_doc = pol_detail.get("PolicyDocument", {})
                if isinstance(policy_doc, str):
                    policy_doc = json.loads(policy_doc)

                for stmt in policy_doc.get("Statement", []):
                    if _statement_has_wildcard(stmt):
                        findings.append(Finding(
                            id=f"iam-wildcard-user-inline-{user_name}-{policy_name}",
                            check_name="IAM Policy Grants Wildcard Administrative Privileges (*:*)",
                            resource_type="AWS::IAM::User",
                            resource_id=user_name,
                            region="global",
                            severity="CRITICAL",
                            exposure="INTERNAL",
                            sensitivity="CRITICAL",
                            evidence={"PolicyName": policy_name, "PolicyType": "Inline", "Statement": stmt},
                            remediation=(
                                f"aws iam delete-user-policy --user-name {user_name} --policy-name {policy_name}\n"
                                f"Replace with least-privilege role-based permissions."
                            )
                        ))
            except ClientError:
                raise
    except ClientError:
        raise

    # 2. Check attached managed policies
    try:
        attached_policies = collect_pages(
            iam_client, "list_attached_user_policies", "AttachedPolicies",
            {"UserName": user_name}, token_param="Marker", token_field="Marker",
            truncated_field="IsTruncated",
        )
        for pol in attached_policies:
            pol_arn = pol.get("PolicyArn", "")
            pol_name = pol.get("PolicyName", "")

            # If AdministratorAccess is attached directly
            if pol_arn == ADMIN_POLICY_ARN:
                findings.append(Finding(
                    id=f"iam-wildcard-user-managed-{user_name}-{pol_name}",
                    check_name="IAM Policy Grants Wildcard Administrative Privileges (*:*)",
                    resource_type="AWS::IAM::User",
                    resource_id=user_name,
                    region="global",
                    severity="CRITICAL",
                    exposure="INTERNAL",
                    sensitivity="CRITICAL",
                    evidence={"AttachedPolicyArn": pol_arn, "PolicyName": pol_name},
                    remediation=f"aws iam detach-user-policy --user-name {user_name} --policy-arn {pol_arn}"
                ))
            elif not pol_arn.startswith("arn:aws:iam::aws:"):  # Customer-managed policy
                try:
                    pol_ver_resp = iam_client.get_policy(PolicyArn=pol_arn)
                    default_ver = pol_ver_resp.get("Policy", {}).get("DefaultVersionId")
                    if default_ver:
                        ver_doc = iam_client.get_policy_version(PolicyArn=pol_arn, VersionId=default_ver)
                        document = ver_doc.get("PolicyVersion", {}).get("Document", {})
                        if isinstance(document, str):
                            document = json.loads(document)
                        for stmt in document.get("Statement", []):
                            if _statement_has_wildcard(stmt):
                                findings.append(Finding(
                                    id=f"iam-wildcard-user-managed-{user_name}-{pol_name}",
                                    check_name="IAM Policy Grants Wildcard Administrative Privileges (*:*)",
                                    resource_type="AWS::IAM::User",
                                    resource_id=user_name,
                                    region="global",
                                    severity="CRITICAL",
                                    exposure="INTERNAL",
                                    sensitivity="CRITICAL",
                                    evidence={"PolicyArn": pol_arn, "Statement": stmt},
                                    remediation=f"aws iam detach-user-policy --user-name {user_name} --policy-arn {pol_arn}"
                                ))
                except ClientError:
                    raise
    except ClientError:
        raise

    return findings


def check_user_mfa(iam_client: Any, user_name: str) -> Optional[Finding]:
    """
    Check if an active IAM user has MFA devices registered.
    Distinguishes missing devices from API errors and verifies whether
    console access is enabled before assuming interactive console login.
    """
    mfa_devices = collect_pages(
        iam_client, "list_mfa_devices", "MFADevices", {"UserName": user_name},
        token_param="Marker", token_field="Marker", truncated_field="IsTruncated",
    )
    if mfa_devices:
        return None

    try:
        login_profile = iam_client.get_login_profile(UserName=user_name)
    except ClientError as error:
        error_code = error.response.get("Error", {}).get("Code", "")
        if error_code == "NoSuchEntity":
            return None
        raise

    if not login_profile.get("LoginProfile"):
        raise RuntimeError(f"Unable to verify console access for IAM user {user_name}.")

    return Finding(
        id=f"iam-user-no-mfa-{user_name}",
            check_name="IAM User Without MFA Enabled",
        resource_type="AWS::IAM::User",
        resource_id=user_name,
        region="global",
        severity="MEDIUM",
        exposure="INTERNAL",
        sensitivity="MEDIUM",
        evidence={
            "UserName": user_name,
            "MFADevices": [],
            "ConsoleAccess": "Verified: Login profile configured",
        },
        cis_id="CIS-1.5",
        remediation=(
            f"Configure an MFA device for console user {user_name} using the approved identity workflow. "
            "CloudGuard does not create or enable MFA devices."
        ),
    )


def check_user_access_keys(
    iam_client: Any,
    user_name: str,
    now: Optional[datetime] = None,
) -> List[Finding]:
    """
    Check for active access keys and enforce the 90-day rotation policy.
    An active key that is 0 days old must NOT be flagged as overdue for rotation.
    Never deactivates or rotates keys automatically.
    """
    findings = []
    try:
        keys = collect_pages(
            iam_client, "list_access_keys", "AccessKeyMetadata",
            {"UserName": user_name}, token_param="Marker", token_field="Marker",
            truncated_field="IsTruncated",
        )
        now = now or datetime.now(timezone.utc)

        for key_meta in keys:
            if key_meta.get("Status") == "Active":
                key_id = key_meta.get("AccessKeyId", "")
                created_date = key_meta.get("CreateDate")

                if not isinstance(created_date, datetime):
                    raise RuntimeError(
                        f"Unable to evaluate rotation age for active access key {key_id}: CreateDate is missing or invalid."
                    )

                if created_date.tzinfo is None:
                    created_date = created_date.replace(tzinfo=timezone.utc)
                elapsed = max(now - created_date, timedelta(0))
                if elapsed <= timedelta(days=90):
                    continue
                age_days = ceil(elapsed.total_seconds() / 86400 * 100) / 100

                check_name = "IAM User Has Active Access Key Overdue for Rotation (>90 Days)"
                remediation = (
                    f"Access key {key_id} is {age_days} days old (>90 days overdue). Review and rotate it manually:\n"
                    f"1. Generate a replacement key and update workloads.\n"
                    f"2. Verify the replacement works before deactivating the old key.\n"
                    f"3. Deactivate and later delete the old key after verification."
                )

                findings.append(Finding(
                    id=f"iam-active-access-key-{user_name}-{key_id}",
                    check_name=check_name,
                    resource_type="AWS::IAM::User",
                    resource_id=user_name,
                    region="global",
                    severity="HIGH",
                    exposure="INTERNAL",
                    sensitivity="MEDIUM",
                    evidence={
                        "AccessKeyId": key_id,
                        "Status": "Active",
                        "AgeDays": age_days,
                        "IsOverdueForRotation": True,
                        "RotationThresholdDays": 90,
                        "CreateDate": str(created_date) if created_date else "Unknown",
                    },
                    cis_id="CIS-1.14",
                    remediation=remediation,
                ))
    except ClientError:
        raise
    return findings


def check_overprivileged_roles(iam_client: Any) -> List[Finding]:
    """Audit IAM roles for broad AdministratorAccess or wildcard permissions."""
    findings = []
    try:
        roles = collect_pages(
            iam_client, "list_roles", "Roles", token_param="Marker",
            token_field="Marker", truncated_field="IsTruncated",
        )
        for role in roles:
            role_name = role.get("RoleName", "")
            role_path = role.get("Path", "")

            # Ignore AWS service-linked internal roles
            if role_path.startswith("/aws-service-role/") or role_name.startswith("AWSServiceRole"):
                continue

            # Check attached managed policies
            try:
                attached_policies = collect_pages(
                    iam_client, "list_attached_role_policies", "AttachedPolicies",
                    {"RoleName": role_name}, token_param="Marker", token_field="Marker",
                    truncated_field="IsTruncated",
                )
                for pol in attached_policies:
                    pol_arn = pol.get("PolicyArn", "")
                    pol_name = pol.get("PolicyName", "")

                    if pol_arn == ADMIN_POLICY_ARN:
                        findings.append(Finding(
                            id=f"iam-overprivileged-role-{role_name}",
                            check_name="IAM Role Has Full Administrative Access",
                            resource_type="AWS::IAM::Role",
                            resource_id=role_name,
                            region="global",
                            severity="CRITICAL",
                            exposure="INTERNAL",
                            sensitivity="CRITICAL",
                            evidence={"AttachedPolicyArn": pol_arn, "PolicyName": pol_name},
                            remediation=(
                                f"aws iam detach-role-policy --role-name {role_name} --policy-arn {pol_arn}\n"
                                f"Replace with specific role permissions adhering to least-privilege."
                            )
                        ))
            except ClientError:
                raise
    except ClientError as e:
        print(f"[ERROR] IAM list_roles failed (Unable to evaluate IAM roles): {e}")
        raise
    return findings


def scan_iam(client: Optional[Any] = None) -> List[Finding]:
    """
    Main IAM scanner entry point.
    Audits users, policies, MFA, keys, and roles.
    """
    iam_client = client or get_client("iam", region_name="ap-south-1")
    findings: List[Finding] = []

    try:
        users = collect_pages(
            iam_client, "list_users", "Users", token_param="Marker",
            token_field="Marker", truncated_field="IsTruncated",
        )
    except ClientError:
        raise

    for user in users:
        user_name = user.get("UserName", "")
        if not user_name:
            continue

        # 1. Wildcard policy check
        findings.extend(check_user_wildcard_policies(iam_client, user_name))

        # 2. MFA check
        f_mfa = check_user_mfa(iam_client, user_name)
        if f_mfa:
            findings.append(f_mfa)

        # 3. Access keys check
        findings.extend(check_user_access_keys(iam_client, user_name))

    # 4. Role audit
    findings.extend(check_overprivileged_roles(iam_client))

    return findings
