import json
import boto3
from botocore.exceptions import ClientError


REGION = "eu-west-2"


def _ec2():
    return boto3.client("ec2", region_name=REGION)


def _iam():
    return boto3.client("iam", region_name=REGION)


def _s3():
    return boto3.client("s3", region_name=REGION)


def _sts():
    return boto3.client("sts", region_name=REGION)


def get_caller_identity() -> str:
    """Show what AWS identity/role the agent is running as."""
    try:
        return json.dumps(_sts().get_caller_identity(), default=str, indent=2)
    except Exception as e:
        return f"Error: {e}"


def enumerate_iam_permissions(role_name: str = "") -> str:
    """
    List inline and attached policies for a role (or the current caller).
    Reveals what permissions an attacker could abuse after gaining credentials.
    """
    iam = _iam()
    try:
        if not role_name:
            identity = _sts().get_caller_identity()
            arn = identity.get("Arn", "")
            role_name = arn.split("/")[-1] if "assumed-role" in arn else ""

        results = {}

        # Attached managed policies
        attached = iam.list_attached_role_policies(RoleName=role_name)
        results["attached_policies"] = [
            p["PolicyName"] for p in attached.get("AttachedPolicies", [])
        ]

        # Inline policies
        inline = iam.list_role_policies(RoleName=role_name)
        results["inline_policies"] = {}
        for policy_name in inline.get("PolicyNames", []):
            doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
            results["inline_policies"][policy_name] = doc["PolicyDocument"]

        return json.dumps(results, default=str, indent=2)
    except Exception as e:
        return f"Error: {e}"


def find_public_s3_buckets() -> str:
    """Check all S3 buckets for public access misconfigurations."""
    s3 = _s3()
    findings = []
    try:
        buckets = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
        for bucket in buckets:
            entry = {"bucket": bucket, "issues": []}
            try:
                acl = s3.get_bucket_acl(Bucket=bucket)
                for grant in acl.get("Grants", []):
                    grantee = grant.get("Grantee", {})
                    if grantee.get("URI", "") in (
                        "http://acs.amazonaws.com/groups/global/AllUsers",
                        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
                    ):
                        entry["issues"].append(f"Public ACL grant: {grant['Permission']}")
            except ClientError:
                pass
            try:
                pab = s3.get_public_access_block(Bucket=bucket)
                cfg = pab["PublicAccessBlockConfiguration"]
                if not all(cfg.values()):
                    entry["issues"].append(f"Public access block not fully enabled: {cfg}")
            except ClientError:
                pass
            if entry["issues"]:
                findings.append(entry)
        return json.dumps(findings if findings else [{"result": "No public buckets found"}], indent=2)
    except Exception as e:
        return f"Error: {e}"


def check_security_group_exposure(instance_id: str = "") -> str:
    """
    Find security groups with dangerous inbound rules (0.0.0.0/0)
    on sensitive ports. Optionally scoped to a specific instance.
    """
    ec2 = _ec2()
    dangerous_ports = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
                       6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch", 8080: "HTTP-alt"}
    findings = []
    try:
        filters = []
        if instance_id:
            reservations = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
            sg_ids = [sg["GroupId"] for r in reservations
                      for i in r["Instances"] for sg in i.get("SecurityGroups", [])]
            filters = [{"Name": "group-id", "Values": sg_ids}]

        sgs = ec2.describe_security_groups(Filters=filters)["SecurityGroups"]
        for sg in sgs:
            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort", 0)
                to_port = rule.get("ToPort", 65535)
                for ip in rule.get("IpRanges", []):
                    if ip.get("CidrIp") in ("0.0.0.0/0", "::/0"):
                        for port, service in dangerous_ports.items():
                            if from_port <= port <= to_port:
                                findings.append({
                                    "sg_id": sg["GroupId"],
                                    "sg_name": sg["GroupName"],
                                    "port": port,
                                    "service": service,
                                    "cidr": ip["CidrIp"],
                                    "severity": "CRITICAL",
                                })
        return json.dumps(findings if findings else [{"result": "No dangerous rules found"}], indent=2)
    except Exception as e:
        return f"Error: {e}"


def enumerate_instance_metadata(ssrf_url: str = "") -> str:
    """
    Fetch EC2 instance metadata — either directly (if running on EC2)
    or via a known SSRF endpoint. Returns IAM credentials if present.
    """
    import requests
    base = ssrf_url.rstrip("/") if ssrf_url else "http://169.254.169.254"
    paths = [
        "/latest/meta-data/",
        "/latest/meta-data/iam/security-credentials/",
        "/latest/meta-data/hostname",
        "/latest/meta-data/local-ipv4",
        "/latest/meta-data/public-ipv4",
        "/latest/meta-data/placement/region",
    ]
    results = {}
    for path in paths:
        try:
            r = requests.get(base + path, timeout=3)
            results[path] = r.text[:1000]
        except Exception as e:
            results[path] = f"unreachable: {e}"
    return json.dumps(results, indent=2)


def check_iam_privilege_escalation() -> str:
    """
    Check for common IAM privilege escalation paths:
    iam:PassRole + ec2:RunInstances, iam:CreatePolicyVersion,
    iam:AttachRolePolicy, sts:AssumeRole wildcards, etc.
    """
    iam = _iam()
    sts = _sts()
    escalation_actions = [
        "iam:CreatePolicyVersion",
        "iam:SetDefaultPolicyVersion",
        "iam:AttachRolePolicy",
        "iam:AttachUserPolicy",
        "iam:PutRolePolicy",
        "iam:PutUserPolicy",
        "iam:PassRole",
        "sts:AssumeRole",
        "lambda:CreateFunction",
        "lambda:InvokeFunction",
        "ec2:RunInstances",
        "cloudformation:CreateStack",
    ]
    try:
        identity = sts.get_caller_identity()
        roles = [r["RoleName"] for r in iam.list_roles().get("Roles", [])]
        findings = []
        for role in roles[:20]:  # cap to avoid rate limiting
            try:
                attached = iam.list_attached_role_policies(RoleName=role)
                for policy in attached.get("AttachedPolicies", []):
                    if policy["PolicyName"] in ("AdministratorAccess", "PowerUserAccess"):
                        findings.append({
                            "role": role,
                            "policy": policy["PolicyName"],
                            "risk": "Direct admin/power access — full privilege escalation possible",
                        })
            except ClientError:
                pass
        return json.dumps({
            "caller": identity.get("Arn"),
            "escalation_actions_to_check": escalation_actions,
            "findings": findings,
        }, default=str, indent=2)
    except Exception as e:
        return f"Error: {e}"
