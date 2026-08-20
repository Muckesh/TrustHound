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


def get_infra_context(ip: str) -> str:
    """
    Query the cloud-agent Neo4j graph for everything known about a public IP:
    EC2 instance details, security group rules, IAM role + policies,
    subnet, VPC, route table. Called on-demand by the web-agent.
    """
    cypher = """
    MATCH (e:EC2Instance)
    WHERE e.public_ip = $ip OR e.private_ip = $ip
    OPTIONAL MATCH (e)-[:LOCATED_IN]->(s:Subnet)-[:BELONGS_TO]->(v:VPC)
    OPTIONAL MATCH (e)-[:USES_SECURITY_GROUP]->(sg:SecurityGroup)
    OPTIONAL MATCH (sg)-[:HAS_RULE]->(r:SGRule)
        WHERE r.direction = 'ingress'
    OPTIONAL MATCH (e)-[:ASSUMES_ROLE]->(role:IAMRole)
    OPTIONAL MATCH (s)-[:USES_ROUTE_TABLE]->(rt:RouteTable)
    RETURN
        e.resource_id        AS instance_id,
        e.name               AS name,
        e.instance_type      AS instance_type,
        e.state              AS state,
        e.public_ip          AS public_ip,
        e.private_ip         AS private_ip,
        v.resource_id        AS vpc_id,
        v.cidr               AS vpc_cidr,
        s.resource_id        AS subnet_id,
        s.availability_zone  AS az,
        rt.has_internet_route AS internet_route,
        rt.has_nat_route     AS nat_route,
        collect(DISTINCT {
            sg_id:       sg.resource_id,
            sg_name:     sg.name,
            port_from:   r.from_port,
            port_to:     r.to_port,
            protocol:    r.protocol,
            cidr:        r.cidr
        }) AS ingress_rules,
        role.name            AS iam_role_name,
        role.arn             AS iam_role_arn
    """
    try:
        driver = _driver()
        with driver.session() as session:
            records = list(session.run(cypher, ip=ip))
        driver.close()

        if not records:
            return json.dumps({"error": f"No EC2 instance found with IP {ip} in graph. Run refresh_graph first."})

        row = dict(records[0])
        # Deduplicate and clean ingress rules
        seen = set()
        clean_rules = []
        for rule in row.get("ingress_rules", []):
            key = (rule.get("sg_id"), rule.get("port_from"), rule.get("cidr"))
            if key not in seen and any(v for v in rule.values()):
                seen.add(key)
                clean_rules.append(rule)
        row["ingress_rules"] = clean_rules

        # Flag high-risk signals
        row["risk_signals"] = []
        if row.get("iam_role_arn"):
            row["risk_signals"].append(f"Has IAM role: {row['iam_role_name']} — check for AdministratorAccess")
        if row.get("internet_route"):
            row["risk_signals"].append("Subnet has direct internet route (public subnet)")
        for rule in clean_rules:
            if rule.get("cidr") in ("0.0.0.0/0", "::/0"):
                row["risk_signals"].append(
                    f"Port {rule.get('port_from')}-{rule.get('port_to')} "
                    f"open to world ({rule.get('cidr')}) on SG {rule.get('sg_id')}"
                )

        return json.dumps(row, default=str, indent=2)
    except Exception as e:
        return f"Graph query error: {e}"
