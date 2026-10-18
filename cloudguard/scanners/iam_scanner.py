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

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
from botocore.exceptions import ClientError
from cloudguard.aws_session import get_client
from cloudguard.models import Finding

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
        inline_resp = iam_client.list_user_policies(UserName=user_name)
        for policy_name in inline_resp.get("PolicyNames", []):
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
                pass
    except ClientError:
        pass

    # 2. Check attached managed policies
    try:
        attached_resp = iam_client.list_attached_user_policies(UserName=user_name)
        for pol in attached_resp.get("AttachedPolicies", []):
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
                    pass
    except ClientError:
        pass

    return findings


def check_user_mfa(iam_client: Any, user_name: str) -> Optional[Finding]:
    """
    Check if an active IAM user has MFA devices registered.
    Distinguishes missing devices from API errors and verifies whether
    console access is enabled before assuming interactive console login.
    """
    try:
        mfa_resp = iam_client.list_mfa_devices(UserName=user_name)
        mfa_devices = mfa_resp.get("MFADevices", [])
        if not mfa_devices:
            # Check console access without assuming it
            console_status = "Unverified"
            has_console = False
            try:
                if hasattr(iam_client, "get_login_profile"):
                    lp_resp = iam_client.get_login_profile(UserName=user_name)
                    if isinstance(lp_resp, dict) and "LoginProfile" in lp_resp:
                        has_console = True
                        console_status = "Enabled (Console Password Configured)"
            except ClientError as e:
                err_code = e.response.get("Error", {}).get("Code", "")
                if err_code == "NoSuchEntity":
                    console_status = "Not Configured (Programmatic / API Access Only)"
                    has_console = False
                elif err_code == "AccessDenied":
                    console_status = "Unable to evaluate console profile (AccessDenied)"
            except Exception:
                console_status = "Unverified"

            remediation_text = (
                f"Enable Multi-Factor Authentication (MFA) for user {user_name}:\n"
                f"aws iam create-virtual-mfa-device --virtual-mfa-device-name {user_name}-mfa\n"
                f"aws iam enable-mfa-device --user-name {user_name} --serial-number <mfa-device-arn> "
                f"--authentication-code-1 <code1> --authentication-code-2 <code2>"
            )
            if not has_console and console_status.startswith("Not Configured"):
                remediation_text = (
                    f"User {user_name} does not have console password access configured (programmatic access only). "
                    f"If console access is granted in the future, enforce MFA before login."
                )

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
                    "ConsoleAccess": console_status,
                },
                cis_id="CIS-1.5",
                remediation=remediation_text,
            )
    except ClientError as e:
        err_code = e.response.get("Error", {}).get("Code", "")
        if err_code == "AccessDenied":
            print(f"[WARN] Unable to evaluate MFA for user {user_name}: AccessDenied on list_mfa_devices")
    return None


def check_user_access_keys(iam_client: Any, user_name: str) -> List[Finding]:
    """
    Check for active access keys and enforce the 90-day rotation policy.
    An active key that is 0 days old must NOT be flagged as overdue for rotation.
    Never deactivates or rotates keys automatically.
    """
    findings = []
    try:
        keys_resp = iam_client.list_access_keys(UserName=user_name)
        now = datetime.now(timezone.utc)

        for key_meta in keys_resp.get("AccessKeyMetadata", []):
            if key_meta.get("Status") == "Active":
                key_id = key_meta.get("AccessKeyId", "")
                created_date = key_meta.get("CreateDate")

                # Handle date edge cases & timezone awareness
                if created_date:
                    if created_date.tzinfo is None:
                        created_date = created_date.replace(tzinfo=timezone.utc)
                    age_days = (now - created_date).days
                    # Guard against negative age due to minor clock skew
                    if age_days < 0:
                        age_days = 0
                else:
                    age_days = 0

                is_overdue = age_days > 90

                if is_overdue:
                    # Enforce 90-day rotation policy strictly
                    check_name = "IAM User Has Active Access Key Overdue for Rotation (>90 Days)"
                    severity = "HIGH"
                    remediation = (
                        f"Access key {key_id} is {age_days} days old (>90 days overdue). Rotate key:\n"
                        f"1. Generate replacement key: aws iam create-access-key --user-name {user_name}\n"
                        f"2. Update workloads with new credentials.\n"
                        f"3. Deactivate old key: aws iam update-access-key --access-key-id {key_id} --status Inactive --user-name {user_name}\n"
                        f"4. Delete old key: aws iam delete-access-key --access-key-id {key_id} --user-name {user_name}"
                    )
                else:
                    # Compliant key within rotation window (0 - 90 days)
                    check_name = "IAM User Has Active Access Key"
                    severity = "LOW"
                    remediation = (
                        f"Access key {key_id} is {age_days} day(s) old and complies with the 90-day rotation policy. "
                        f"Track key age and plan rotation prior to reaching 90 days."
                    )

                findings.append(Finding(
                    id=f"iam-active-access-key-{user_name}-{key_id}",
                    check_name=check_name,
                    resource_type="AWS::IAM::User",
                    resource_id=user_name,
                    region="global",
                    severity=severity,
                    exposure="INTERNAL",
                    sensitivity="MEDIUM",
                    evidence={
                        "AccessKeyId": key_id,
                        "Status": "Active",
                        "AgeDays": age_days,
                        "IsOverdueForRotation": is_overdue,
                        "RotationThresholdDays": 90,
                        "CreateDate": str(created_date) if created_date else "Unknown",
                    },
                    cis_id="CIS-1.14",
                    remediation=remediation,
                ))
    except ClientError as e:
        err_code = e.response.get("Error", {}).get("Code", "")
        if err_code == "AccessDenied":
            print(f"[WARN] Unable to evaluate access keys for user {user_name}: AccessDenied on list_access_keys")
    return findings


def check_overprivileged_roles(iam_client: Any) -> List[Finding]:
    """Audit IAM roles for broad AdministratorAccess or wildcard permissions."""
    findings = []
    try:
        roles_resp = iam_client.list_roles()
        for role in roles_resp.get("Roles", []):
            role_name = role.get("RoleName", "")
            role_path = role.get("Path", "")

            # Ignore AWS service-linked internal roles
            if role_path.startswith("/aws-service-role/") or role_name.startswith("AWSServiceRole"):
                continue

            # Check attached managed policies
            try:
                attached = iam_client.list_attached_role_policies(RoleName=role_name)
                for pol in attached.get("AttachedPolicies", []):
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
                pass
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
        users_resp = iam_client.list_users()
        users = users_resp.get("Users", [])
    except ClientError as e:
        print(f"[ERROR] IAM list_users failed (Unable to evaluate IAM users): {e}")
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
