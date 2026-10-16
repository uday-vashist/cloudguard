"""
CloudGuard EC2 Security Group Scanner.

Audits Amazon EC2 Security Groups for unrestricted public inbound access (0.0.0.0/0 or ::/0)
on sensitive administrative and database ports:
1. Administrative Ports:
   - SSH (TCP Port 22) - Remote shell access
   - RDP (TCP Port 3389) - Windows Remote Desktop
2. Database / Data Store Ports:
   - MySQL / Aurora (TCP Port 3306)
   - PostgreSQL (TCP Port 5432)
   - Microsoft SQL Server (TCP Port 1433)
   - MongoDB (TCP Port 27017)
   - Redis (TCP Port 6379)
   - Oracle DB (TCP Port 1521)

VIVA CONCEPTS:
- Network Perimeter Security & Zero Trust: Direct internet access to management or
  database ports allows brute-force attacks, credential stuffing, and remote code execution.
  These ports should only be accessible through bastion hosts, VPNs, or AWS Systems Manager (SSM).
- Read-Only Compliance: Only calls ec2.describe_security_groups.
"""

from typing import Any, Dict, List, Optional
from botocore.exceptions import ClientError
from cloudguard.aws_session import get_client
from cloudguard.models import Finding

# Dictionary of sensitive ports with metadata: (service_name, severity, sensitivity, cis_id)
SENSITIVE_PORTS: Dict[int, Dict[str, str]] = {
    22: {
        "service": "SSH",
        "severity": "CRITICAL",
        "sensitivity": "HIGH",
        "cis_id": "CIS-5.2",
        "desc": "Remote terminal administration"
    },
    3389: {
        "service": "RDP",
        "severity": "CRITICAL",
        "sensitivity": "HIGH",
        "cis_id": "CIS-5.3",
        "desc": "Windows Remote Desktop Protocol"
    },
    3306: {
        "service": "MySQL/Aurora",
        "severity": "CRITICAL",
        "sensitivity": "CRITICAL",
        "cis_id": "CIS-5.4",
        "desc": "Relational database server"
    },
    5432: {
        "service": "PostgreSQL",
        "severity": "CRITICAL",
        "sensitivity": "CRITICAL",
        "cis_id": "CIS-5.4",
        "desc": "PostgreSQL database server"
    },
    1433: {
        "service": "MSSQL",
        "severity": "CRITICAL",
        "sensitivity": "CRITICAL",
        "cis_id": "CIS-5.4",
        "desc": "Microsoft SQL database server"
    },
    27017: {
        "service": "MongoDB",
        "severity": "CRITICAL",
        "sensitivity": "CRITICAL",
        "cis_id": "CIS-5.4",
        "desc": "MongoDB document database"
    },
    6379: {
        "service": "Redis",
        "severity": "CRITICAL",
        "sensitivity": "CRITICAL",
        "cis_id": "CIS-5.4",
        "desc": "Redis in-memory cache/store"
    },
    1521: {
        "service": "Oracle DB",
        "severity": "CRITICAL",
        "sensitivity": "CRITICAL",
        "cis_id": "CIS-5.4",
        "desc": "Oracle relational database"
    },
}


def _is_public_cidr(cidr: str) -> bool:
    """Check if CIDR block represents open public internet."""
    return cidr in ("0.0.0.0/0", "::/0")


def check_security_group_ingress(sg: Dict[str, Any], region: str) -> List[Finding]:
    """
    Evaluates ingress rules of a security group against sensitive ports.
    """
    findings: List[Finding] = []
    sg_id = sg.get("GroupId", "")
    sg_name = sg.get("GroupName", sg_id)
    ip_permissions = sg.get("IpPermissions", [])

    for perm in ip_permissions:
        ip_protocol = perm.get("IpProtocol", "")
        from_port = perm.get("FromPort")
        to_port = perm.get("ToPort")

        # Collect all public CIDR blocks present in this rule
        public_cidrs = []
        for ip_range in perm.get("IpRanges", []):
            cidr = ip_range.get("CidrIp", "")
            if _is_public_cidr(cidr):
                public_cidrs.append(cidr)
        for ipv6_range in perm.get("Ipv6Ranges", []):
            cidr = ipv6_range.get("CidrIpv6", "")
            if _is_public_cidr(cidr):
                public_cidrs.append(cidr)

        if not public_cidrs:
            continue

        # Evaluate which sensitive ports are encompassed by this ingress rule
        for port, meta in SENSITIVE_PORTS.items():
            port_exposed = False

            if ip_protocol == "-1":
                # All traffic allowed (0 - 65535)
                port_exposed = True
            elif ip_protocol in ("tcp", "6"):
                if from_port is not None and to_port is not None:
                    if from_port <= port <= to_port:
                        port_exposed = True

            if port_exposed:
                check_title = f"Security Group Ingress Allows Port {port} ({meta['service']}) from 0.0.0.0/0"
                finding_id = f"sg-open-{port}-{sg_id}"

                findings.append(Finding(
                    id=finding_id,
                    check_name=check_title,
                    resource_type="AWS::EC2::SecurityGroup",
                    resource_id=sg_id,
                    region=region,
                    severity=meta["severity"],
                    exposure="PUBLIC",
                    sensitivity=meta["sensitivity"],
                    evidence={
                        "GroupId": sg_id,
                        "GroupName": sg_name,
                        "Protocol": ip_protocol,
                        "FromPort": from_port,
                        "ToPort": to_port,
                        "ExposedPort": port,
                        "Service": meta["service"],
                        "PublicCidrs": public_cidrs,
                    },
                    cis_id=meta["cis_id"],
                    remediation=(
                        f"Revoke ingress rule for port {port} on Security Group {sg_id}:\n"
                        f"aws ec2 revoke-security-group-ingress --group-id {sg_id} "
                        f"--protocol tcp --port {port} --cidr 0.0.0.0/0\n"
                        f"Restrict access to known corporate IP addresses or use AWS SSM Session Manager."
                    )
                ))

    return findings


def scan_security_groups(client: Optional[Any] = None, region_name: str = "ap-south-1") -> List[Finding]:
    """
    Main Security Group scanner entry point.
    Audits all Security Groups in the specified region.
    """
    ec2_client = client or get_client("ec2", region_name=region_name)
    findings: List[Finding] = []

    try:
        paginator = ec2_client.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page.get("SecurityGroups", []):
                findings.extend(check_security_group_ingress(sg, region_name))
    except (ClientError, AttributeError):
        # Fallback if paginator not supported by mock or custom client
        try:
            resp = ec2_client.describe_security_groups()
            for sg in resp.get("SecurityGroups", []):
                findings.extend(check_security_group_ingress(sg, region_name))
        except ClientError as e:
            print(f"[WARN] EC2 describe_security_groups failed: {e}")

    return findings
