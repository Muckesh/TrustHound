"""
Orchestrator — coordinates cloud-agent graph + web-agent exploitation.

Flow:
  1. Query Neo4j for all public EC2 instances, rank by risk score
  2. For each target (highest risk first):
       - Pass IP + focused brief to web-agent
       - Web-agent calls get_infra_context(ip) on-demand for graph context
       - Web-agent runs active exploitation
  3. Aggregate all findings into a final report
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "web-agent"))

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

from graph import get_ranked_targets
from agent.agent import run_agent as web_agent_run


def _target_brief(target: dict) -> str:
    lines = [
        f"Target IP: {target['attack_ip']}",
        f"Public IP: {target.get('public_ip') or 'none'}  Private IP: {target.get('private_ip') or 'none'}",
        f"Instance: {target['name']} ({target['instance_id']}) — state: {target['state']}",
        f"Risk score: {target['risk_score']} — reasons: {', '.join(target['risk_reasons']) or 'none'}",
        "",
        "Use get_infra_context tool to pull full graph context (SG rules, IAM role, VPC topology).",
        "Then run active exploitation based on what you find.",
    ]
    return "\n".join(lines)


def run_orchestrator(max_targets: int = 3, verbose: bool = True) -> str:
    print("=" * 60)
    print("ORCHESTRATOR — Cloud + Web Agent")
    print("=" * 60)

    # Step 1: Get ranked targets from graph
    print("\n[1] Querying cloud graph for attack surface...")
    targets = get_ranked_targets()

    if not targets:
        return "No public EC2 instances found in graph. Run cloud-agent refresh first."

    print(f"    Found {len(targets)} public instance(s), attacking top {min(max_targets, len(targets))}:\n")
    for i, t in enumerate(targets[:max_targets], 1):
        ip_display = t.get('public_ip') or t.get('private_ip', 'no-ip')
        print(f"    #{i} {t['name']} ({ip_display}) [{t['reachable']}] — risk score: {t['risk_score']}")
        for r in t['risk_reasons']:
            print(f"        • {r}")

    # Step 2: Attack each target
    all_findings = []
    for i, target in enumerate(targets[:max_targets], 1):
        ip = target["attack_ip"]
        print(f"\n{'─'*60}")
        print(f"[{i}/{min(max_targets, len(targets))}] Attacking {target['name']} ({ip}) [{target['reachable']}]")
        print(f"{'─'*60}\n")

        if target["reachable"] == "private-only":
            note = "This instance has no public IP — only reachable from within the VPC or via VPN/bastion."
            objective = (
                f"Assess {ip} (private-only — NOT reachable over the network from this machine). "
                f"DO NOT run port scans or any network probes — they will all time out. "
                f"Instead: "
                f"1. Call get_infra_context('{ip}') for graph context. "
                f"2. Run cloud enumeration only: get_caller_identity, enumerate_iam_permissions, "
                f"   find_public_s3_buckets, check_iam_privilege_escalation, check_security_group_exposure. "
                f"3. Write a concise findings report covering IAM risk, SG exposure, and reachability."
            )
        else:
            note = "This instance has a public IP and is directly internet-facing."
            objective = (
                f"Perform a full pentest on {ip}. "
                f"Start with get_infra_context('{ip}') to get the infrastructure context from the graph, "
                f"then run active exploitation based on what you find. "
                f"Test all open ports, exploit any vulnerabilities found, "
                f"and check for privilege escalation via the IAM role. "
                f"Write a concise findings report."
            )

        context = _target_brief(target) + f"\nNote: {note}"
        report = web_agent_run(objective=objective, context=context, verbose=verbose)
        all_findings.append({
            "target": f"{target['name']} ({ip})",
            "risk_score": target["risk_score"],
            "report": report,
        })

    # Step 3: Aggregate
    print(f"\n{'='*60}")
    print("FINAL ORCHESTRATOR REPORT")
    print(f"{'='*60}\n")

    summary_lines = [
        f"# Security Assessment Report",
        f"Targets assessed: {len(all_findings)}",
        "",
    ]
    for idx, finding in enumerate(all_findings, 1):
        summary_lines.append(f"## Target {idx}: {finding['target']} (risk score: {finding['risk_score']})")
        summary_lines.append(finding["report"])
        summary_lines.append("")

    return "\n".join(summary_lines)


def main():
    max_targets = int(os.environ.get("MAX_TARGETS", "3"))
    report = run_orchestrator(max_targets=max_targets)
    print(report)


if __name__ == "__main__":
    main()
