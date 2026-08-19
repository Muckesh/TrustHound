"""
Query the cloud-agent Neo4j graph to produce a ranked attack surface.
No LLM needed — pure graph queries.
"""
import json
import os

from neo4j import GraphDatabase


def _driver():
    return GraphDatabase.driver(
        os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
        auth=(
            os.environ.get("NEO4J_USERNAME", "neo4j"),
            os.environ.get("NEO4J_PASSWORD", "hackathon"),
        ),
    )


def get_ranked_targets() -> list[dict]:
    """
    Return all public-facing EC2 instances ranked by attack priority.

    Risk scoring:
      +4  IAM role with dangerous policy (AdministratorAccess / PowerUserAccess)
      +3  Ingress rule open to 0.0.0.0/0
      +2  Instance is in a public subnet (has internet route)
      +1  Instance is running
    """
    cypher = """
    MATCH (e:EC2Instance)
    WHERE e.state = 'running'
    OPTIONAL MATCH (e)-[:LOCATED_IN]->(s:Subnet)-[:USES_ROUTE_TABLE]->(rt:RouteTable)
    OPTIONAL MATCH (e)-[:USES_SECURITY_GROUP]->(sg:SecurityGroup)-[:HAS_RULE]->(r:SGRule)
        WHERE r.direction = 'ingress' AND r.cidr IN ['0.0.0.0/0', '::/0']
    OPTIONAL MATCH (e)-[:ASSUMES_ROLE]->(role:IAMRole)
    RETURN
        e.resource_id        AS instance_id,
        e.name               AS name,
        e.public_ip          AS public_ip,
        e.private_ip         AS private_ip,
        e.instance_type      AS instance_type,
        e.state              AS state,
        rt.has_internet_route AS internet_route,
        collect(DISTINCT {
            port_from: r.from_port,
            port_to:   r.to_port,
            protocol:  r.protocol,
            cidr:      r.cidr,
            sg_id:     sg.resource_id
        }) AS open_rules,
        role.name            AS iam_role_name,
        role.arn             AS iam_role_arn
    ORDER BY e.name
    """
    _DANGEROUS_POLICIES = {
        "AdministratorAccess", "PowerUserAccess",
        "AWSLakeFormationDataAdmin", "AmazonElasticMapReduceFullAccess",
    }

    driver = _driver()
    with driver.session() as session:
        records = list(session.run(cypher))
    driver.close()

    targets = []
    for rec in records:
        row = dict(rec)
        score = 0
        reasons = []

        if row.get("state") == "running":
            score += 1

        if row.get("internet_route"):
            score += 2
            reasons.append("public subnet")

        open_rules = [r for r in (row.get("open_rules") or []) if r.get("cidr")]
        if open_rules:
            score += 3
            for rule in open_rules:
                reasons.append(
                    f"port {rule.get('port_from')}-{rule.get('port_to')} "
                    f"open to {rule.get('cidr')}"
                )

        iam_arn = row.get("iam_role_arn") or ""
        if any(p in iam_arn or p == row.get("iam_role_name") for p in _DANGEROUS_POLICIES):
            score += 4
            reasons.append(f"dangerous IAM role: {row.get('iam_role_name')}")
        elif iam_arn:
            score += 1
            reasons.append(f"has IAM role: {row.get('iam_role_name')}")

        # Use public IP if available, fall back to private IP
        attack_ip = row.get("public_ip") or row.get("private_ip")
        targets.append({
            "instance_id": row["instance_id"],
            "name": row.get("name") or row["instance_id"],
            "public_ip": row.get("public_ip"),
            "private_ip": row.get("private_ip"),
            "attack_ip": attack_ip,
            "reachable": "public" if row.get("public_ip") else "private-only",
            "state": row.get("state"),
            "iam_role": row.get("iam_role_name"),
            "open_rules": open_rules,
            "risk_score": score,
            "risk_reasons": reasons,
        })

    targets.sort(key=lambda t: t["risk_score"], reverse=True)
    return targets
