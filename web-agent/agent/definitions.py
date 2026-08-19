from tools.scanner import port_scan, web_fingerprint, web_scan, vuln_scan, dir_enum, exploit_search
from tools.http import http_request, ssrf_metadata
from tools.infra import get_infra_context
from tools.aws_enum import (
    get_caller_identity,
    enumerate_iam_permissions,
    find_public_s3_buckets,
    check_security_group_exposure,
    enumerate_instance_metadata,
    check_iam_privilege_escalation,
)
from tools.exploit import run_command, ssh_command, check_privesc_linux

import json


def _j(x):
    return json.dumps(x) if isinstance(x, dict) else str(x)


FUNCTIONS = {
    "get_infra_context":            lambda a: get_infra_context(a["ip"]),
    "port_scan":                    lambda a: port_scan(a["target"], a.get("ports", ""), a.get("flags", "")),
    "web_fingerprint":              lambda a: web_fingerprint(a["target"]),
    "web_scan":                     lambda a: web_scan(a["target"]),
    "vuln_scan":                    lambda a: vuln_scan(a["target"], a.get("templates", "")),
    "dir_enum":                     lambda a: dir_enum(a["target"], a.get("wordlist", ""), a.get("extensions", "php,html,js,txt,bak")),
    "exploit_search":               lambda a: exploit_search(a["query"]),
    "http_request":                 lambda a: http_request(a["url"], a.get("method", "GET"), a.get("headers"), a.get("body", "")),
    "ssrf_metadata":                lambda a: ssrf_metadata(a["target_url"]),
    "get_caller_identity":          lambda a: get_caller_identity(),
    "enumerate_iam_permissions":    lambda a: enumerate_iam_permissions(a.get("role_name", "")),
    "find_public_s3_buckets":       lambda a: find_public_s3_buckets(),
    "check_security_group_exposure":lambda a: check_security_group_exposure(a.get("instance_id", "")),
    "enumerate_instance_metadata":  lambda a: enumerate_instance_metadata(a.get("ssrf_url", "")),
    "check_iam_privilege_escalation": lambda a: check_iam_privilege_escalation(),
    "run_command":                  lambda a: run_command(a["command"], a.get("timeout", 60)),
    "ssh_command":                  lambda a: ssh_command(a["host"], a["user"], a["command"], a.get("key_path", ""), a.get("password", "")),
    "check_privesc_linux":          lambda a: check_privesc_linux(a["host"], a["user"], a.get("key_path", ""), a.get("password", "")),
}

DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "get_infra_context",
            "description": (
                "Query the cloud-agent Neo4j graph for everything known about a target IP: "
                "EC2 instance details, open security group rules, IAM role, subnet, VPC, "
                "route table, and pre-computed risk signals. "
                "Call this FIRST before port_scan to get free context from the infra graph."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {"type": "string", "description": "Public or private IP of the target"},
                },
                "required": ["ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "port_scan",
            "description": "nmap port scan with service/version detection. Use first on any new target to discover open ports and running services.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "IP address or hostname"},
                    "ports":  {"type": "string", "description": "Port range e.g. '80,443,22' or '1-1000'. Leave empty for top 1000."},
                    "flags":  {"type": "string", "description": "Extra nmap flags e.g. '-A -T4 --script vuln'"},
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "web_fingerprint",
            "description": "whatweb — identify web technologies, CMS, frameworks, and server headers.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "URL or IP (http:// prefix optional)"},
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "web_scan",
            "description": "nikto — comprehensive web server scan for misconfigurations, outdated software, dangerous files.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "URL or IP"},
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "vuln_scan",
            "description": "nuclei — template-based vulnerability scanner. Detects CVEs, misconfigs, exposed panels, injection points.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target":    {"type": "string", "description": "URL or IP"},
                    "templates": {"type": "string", "description": "Nuclei template path or tag e.g. 'cves' or 'exposures'. Leave empty for all."},
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "dir_enum",
            "description": "gobuster — brute-force directories and files on a web server. Use after web_fingerprint to find hidden endpoints.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target":     {"type": "string", "description": "Base URL"},
                    "wordlist":   {"type": "string", "description": "Path to wordlist. Defaults to dirb/common.txt"},
                    "extensions": {"type": "string", "description": "File extensions to try e.g. 'php,html,js,bak'"},
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "exploit_search",
            "description": "searchsploit — search Exploit-DB for public exploits matching a service name and version.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Service name + version e.g. 'Apache 2.4.49' or 'OpenSSH 7.2'"},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "http_request",
            "description": "Send a raw HTTP request. Use to manually test endpoints, inject payloads, check auth bypasses, LFI, SQLi etc.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url":              {"type": "string"},
                    "method":           {"type": "string", "description": "GET, POST, PUT, DELETE, etc.", "default": "GET"},
                    "headers":          {"type": "object", "description": "Key-value HTTP headers"},
                    "body":             {"type": "string", "description": "Request body for POST/PUT"},
                    "follow_redirects": {"type": "boolean", "default": True},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "ssrf_metadata",
            "description": "Test a URL parameter for SSRF by probing the AWS EC2 metadata endpoint (169.254.169.254). Provide a target URL that accepts a url/redirect parameter.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target_url": {"type": "string", "description": "The vulnerable endpoint URL to probe"},
                },
                "required": ["target_url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_caller_identity",
            "description": "Show what AWS IAM identity the agent is currently operating as.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "enumerate_iam_permissions",
            "description": "List all policies (managed + inline) attached to an IAM role. Reveals what an attacker can do with stolen credentials.",
            "parameters": {
                "type": "object",
                "properties": {
                    "role_name": {"type": "string", "description": "IAM role name. Leave empty to use the current caller's role."},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "find_public_s3_buckets",
            "description": "Scan all S3 buckets for public ACLs and disabled public access blocks.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_security_group_exposure",
            "description": "Find security groups with 0.0.0.0/0 rules on dangerous ports (SSH, RDP, databases). Optionally filter by instance.",
            "parameters": {
                "type": "object",
                "properties": {
                    "instance_id": {"type": "string", "description": "EC2 instance ID to scope the check. Leave empty to check all SGs."},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "enumerate_instance_metadata",
            "description": "Fetch EC2 instance metadata (hostname, IP, IAM credentials). Run directly if on EC2, or pass an ssrf_url to exploit SSRF.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ssrf_url": {"type": "string", "description": "SSRF proxy URL if not running on EC2 directly. Leave empty to hit 169.254.169.254 directly."},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_iam_privilege_escalation",
            "description": "Scan IAM roles for privilege escalation paths: admin policies, PassRole abuse, CreatePolicyVersion, etc.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_command",
            "description": "Run a shell command locally. Use for exploit PoCs, payload generation, post-exploitation scripts.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "Shell command to run"},
                    "timeout": {"type": "integer", "description": "Timeout in seconds", "default": 60},
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "ssh_command",
            "description": "Run a command on a remote host over SSH. Use after gaining credentials for post-exploitation.",
            "parameters": {
                "type": "object",
                "properties": {
                    "host":     {"type": "string"},
                    "user":     {"type": "string"},
                    "command":  {"type": "string"},
                    "key_path": {"type": "string", "description": "Path to SSH private key"},
                    "password": {"type": "string", "description": "SSH password (if no key)"},
                },
                "required": ["host", "user", "command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_privesc_linux",
            "description": "Run a full suite of Linux privilege escalation checks on a remote host: sudo rights, SUID binaries, cron jobs, capabilities, docker socket, kernel version.",
            "parameters": {
                "type": "object",
                "properties": {
                    "host":     {"type": "string"},
                    "user":     {"type": "string"},
                    "key_path": {"type": "string", "description": "Path to SSH private key"},
                    "password": {"type": "string"},
                },
                "required": ["host", "user"],
            },
        },
    },
]
