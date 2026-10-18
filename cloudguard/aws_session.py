"""
AWS Session and Read-Only Safety Guard for CloudGuard.

Why this file exists:
1. VIVA CONCEPT: "Principle of Least Privilege & Defense-in-Depth".
   Even if an AWS IAM credential accidentally possesses write or admin permissions,
   CloudGuard MUST guarantee at the application layer that it never modifies, creates,
   or deletes any AWS resources.
2. Intercepts calls via the Proxy Pattern: Wraps the standard boto3 client and checks
   the operation name BEFORE any HTTP request leaves the machine.
3. Enforces profile 'cloudguard' and region 'ap-south-1' as required by project constraints.

Design Decisions & Alternatives:
- Why Proxy Pattern? We wrap boto3 clients in `ReadOnlyClientWrapper` instead of monkey-patching
  botocore globally. This isolates safety checks cleanly and is easy to explain during viva.
- Alternative considered: Relying only on AWS IAM policy.
  Rejected as primary defense because IAM misconfigurations happen; code-level guards provide
  fail-safe defense-in-depth.
"""

from typing import Any, Callable, Set
import boto3
from botocore.exceptions import ProfileNotFound, NoCredentialsError


# Hard constraint: Allowed read-only operation prefixes
ALLOWED_METHOD_PREFIXES = ("get_", "list_", "describe_")

# Standard boto3 client utility methods and attributes that do not make AWS API mutations
ALLOWED_CLIENT_UTILITIES: Set[str] = {
    "can_paginate",
    "get_paginator",
    "get_waiter",
    "exceptions",
    "meta",
    "close",
}

# Mutation keywords explicitly blocked (for descriptive viva error messages)
MUTATING_KEYWORDS = (
    "create", "put", "delete", "update", "modify",
    "attach", "detach", "authorize", "revoke", "remove",
    "enable", "disable", "start", "stop", "terminate",
    "reboot", "set_", "reset_"
)

DEFAULT_PROFILE = "cloudguard"
DEFAULT_REGION = "ap-south-1"


class ReadOnlyViolationError(PermissionError):
    """Raised whenever a mutating or non-whitelisted AWS operation is attempted."""
    pass


class ReadOnlyClientWrapper:
    """
    A protective proxy around a boto3 client that inspects every attribute/method call.
    Only allows read-only calls (get_*, list_*, describe_*) and blocks all mutations.
    """

    def __init__(self, raw_client: Any, service_name: str):
        # Use object.__setattr__ to avoid recursive __getattr__ calls
        object.__setattr__(self, "_ReadOnlyClientWrapper__raw_client", raw_client)
        object.__setattr__(self, "_service_name", service_name)

    def __getattribute__(self, name: str) -> Any:
        if name in {"_raw_client", "_ReadOnlyClientWrapper__raw_client", "__dict__"}:
            raise AttributeError("The underlying AWS client is private to the read-only wrapper.")
        return object.__getattribute__(self, name)

    def _validate_operation(self, operation_name: str) -> None:
        """Validate whether an operation is strictly read-only."""
        op_lower = operation_name.lower()

        # AWS read APIs may contain mutation words, e.g. list_attached_user_policies.
        # Classify by the operation's read-only verb before inspecting its name.
        if any(op_lower.startswith(prefix) for prefix in ALLOWED_METHOD_PREFIXES):
            return

        # 2. Name common mutations in the rejection message; all other operations
        # remain denied below, so this list is descriptive rather than an allowlist.
        for keyword in MUTATING_KEYWORDS:
            if op_lower.startswith(keyword):
                raise ReadOnlyViolationError(
                    f"[CloudGuard Read-Only Guard] Blocked mutating operation '{operation_name}' on AWS {self._service_name} client. "
                    f"CloudGuard strictly prohibits write/mutation actions ('{keyword}')."
                )

        raise ReadOnlyViolationError(
            f"[CloudGuard Read-Only Guard] Blocked call to '{operation_name}' on AWS {self._service_name} client. "
            f"CloudGuard is strictly read-only and only permits get_*, list_*, and describe_* operations."
        )

    def _wrap_paginator(self, original_get_paginator: Callable) -> Callable:
        """Ensure paginators only execute read-only operations."""
        def wrapped_get_paginator(operation_name: str, *args, **kwargs):
            # Normalizing operation name (e.g. 'list_buckets' or 'ListBuckets')
            normalized_op = operation_name.lower().replace("_", "")
            if not (
                normalized_op.startswith("get")
                or normalized_op.startswith("list")
                or normalized_op.startswith("describe")
            ):
                raise ReadOnlyViolationError(
                    f"[CloudGuard Read-Only Guard] Blocked paginator for mutating operation '{operation_name}'."
                )
            return original_get_paginator(operation_name, *args, **kwargs)

        return wrapped_get_paginator

    def _wrap_waiter(self, original_get_waiter: Callable) -> Callable:
        """Ensure waiters only wait on non-destructive states."""
        def wrapped_get_waiter(waiter_name: str, *args, **kwargs):
            w_lower = waiter_name.lower()
            if any(term in w_lower for term in ("delete", "terminate", "destroy")):
                raise ReadOnlyViolationError(
                    f"[CloudGuard Read-Only Guard] Blocked waiter '{waiter_name}' for destructive operation."
                )
            return original_get_waiter(waiter_name, *args, **kwargs)

        return wrapped_get_waiter

    def __getattr__(self, name: str) -> Any:
        # Allow internal python attributes and whitelisted client utilities
        if name.startswith("_") or name in ALLOWED_CLIENT_UTILITIES:
            if name.startswith("_"):
                raise AttributeError(f"'{type(self).__name__}' has no exposed attribute '{name}'.")
            raw_client = object.__getattribute__(self, "_ReadOnlyClientWrapper__raw_client")
            attr = getattr(raw_client, name)
            if name == "get_paginator":
                return self._wrap_paginator(attr)
            if name == "get_waiter":
                return self._wrap_waiter(attr)
            return attr

        # Check if this is an AWS API operation
        self._validate_operation(name)

        # Retrieve and return the raw client attribute
        raw_client = object.__getattribute__(self, "_ReadOnlyClientWrapper__raw_client")
        return getattr(raw_client, name)

    def __repr__(self) -> str:
        return f"<ReadOnlyClientWrapper service='{self._service_name}'>"


class CloudGuardSession:
    """
    Manages AWS connectivity using the dedicated 'cloudguard' profile
    and produces ReadOnlyClientWrapper instances.
    """

    def __init__(self, profile_name: str = DEFAULT_PROFILE, region_name: str = DEFAULT_REGION):
        self.profile_name = profile_name
        self.region_name = region_name
        try:
            self._session = boto3.Session(
                profile_name=self.profile_name,
                region_name=self.region_name
            )
        except ProfileNotFound as e:
            raise RuntimeError(
                f"AWS profile '{self.profile_name}' not found. "
                f"Please configure it using 'aws configure --profile {self.profile_name}'."
            ) from e

    def client(self, service_name: str, region_name: str | None = None) -> ReadOnlyClientWrapper:
        """
        Creates a read-only wrapped AWS service client.
        """
        target_region = region_name or self.region_name
        raw_client = self._session.client(service_name, region_name=target_region)
        return ReadOnlyClientWrapper(raw_client, service_name)


def get_session(profile_name: str = DEFAULT_PROFILE, region_name: str = DEFAULT_REGION) -> CloudGuardSession:
    """Convenience helper to obtain a CloudGuardSession."""
    return CloudGuardSession(profile_name=profile_name, region_name=region_name)


def get_client(service_name: str, region_name: str = DEFAULT_REGION, profile_name: str = DEFAULT_PROFILE) -> ReadOnlyClientWrapper:
    """Convenience helper to obtain a read-only wrapped client for an AWS service."""
    session = get_session(profile_name=profile_name, region_name=region_name)
    return session.client(service_name=service_name, region_name=region_name)
