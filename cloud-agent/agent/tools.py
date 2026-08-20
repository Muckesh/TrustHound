import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from graph.builder import Neo4jCloudGraph, build_cloud_graph
from aws.ec2 import list_ec2_instances
from aws.iam import list_iam_roles
from aws.route_tables import list_route_tables
from aws.s3 import list_s3_buckets
from aws.vpc import list_vpcs, list_subnets
from aws.security_groups import list_security_groups


def _connect():
    return Neo4jCloudGraph(
        uri=os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
        username=os.environ.get("NEO4J_USERNAME", "neo4j"),
        password=os.environ.get("NEO4J_PASSWORD", "hackathon"),
    )


def _sanitize_cypher(cypher: str) -> str:
    # Models sometimes write {prop: NOT NULL} in MATCH clauses which is invalid.
    # Strip these property map entries so the query still runs.
    cypher = re.sub(r'\{\s*\w+\s*:\s*NOT\s+NULL\s*\}', '', cypher)
    # Also strip partial property maps like {a: 1, b: NOT NULL} → {a: 1}
    cypher = re.sub(r',\s*\w+\s*:\s*NOT\s+NULL', '', cypher)
    cypher = re.sub(r'\w+\s*:\s*NOT\s+NULL\s*,', '', cypher)
    return cypher.strip()


def query_graph(cypher: str) -> str:
    cypher = _sanitize_cypher(cypher)
    try:
        with _connect() as graph:
            records = graph.query(cypher)
        result = [dict(record) for record in records]
        return json.dumps(result, default=str, indent=2)
    except Exception as e:
        return f"Query error: {e}"


def get_schema() -> str:
    try:
        with _connect() as graph:
            labels = [
                r["label"]
                for r in graph.query(
                    "CALL db.labels() YIELD label RETURN label ORDER BY label"
                )
            ]

            lines = ["Node counts:"]
            for label in labels:
                count = graph.query(
                    f"MATCH (n:{label}) RETURN count(n) AS c"
                )[0]["c"]
                lines.append(f"  {label}: {count}")

            rel_types = [
                r["relationshipType"]
                for r in graph.query(
                    "CALL db.relationshipTypes() YIELD relationshipType "
                    "RETURN relationshipType ORDER BY relationshipType"
                )
            ]

            lines.append("\nRelationship counts:")
            for rel in rel_types:
                count = graph.query(
                    f"MATCH ()-[r:{rel}]->() RETURN count(r) AS c"
                )[0]["c"]
                lines.append(f"  {rel}: {count}")

        return "\n".join(lines)
    except Exception as e:
        return f"Schema error: {e}"


def refresh_graph() -> str:
    try:
        vpcs = list_vpcs()
        subnets = list_subnets()
        instances = list_ec2_instances()
        security_groups = list_security_groups()
        roles = list_iam_roles()
        buckets = list_s3_buckets()
        route_tables = list_route_tables()

        with build_cloud_graph(
            vpcs=vpcs,
            subnets=subnets,
            instances=instances,
            security_groups=security_groups,
            roles=roles,
            buckets=buckets,
            route_tables=route_tables,
        ) as graph:
            nodes = graph.node_count()
            edges = graph.edge_count()

        return (
            f"Graph rebuilt.\n"
            f"  VPCs: {len(vpcs)}, Subnets: {len(subnets)}, "
            f"EC2: {len(instances)}, SGs: {len(security_groups)}\n"
            f"  IAM roles: {len(roles)}, S3: {len(buckets)}, "
            f"Route tables: {len(route_tables)}\n"
            f"  Total: {nodes} nodes, {edges} edges"
        )
    except Exception as e:
        return f"Refresh error: {e}"


DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "query_graph",
            "description": (
                "Run a Cypher query against the Neo4j AWS infrastructure graph. "
                "Returns results as JSON. If the query fails, the error is returned so you can fix it. "
                "Always return specific properties (e.g. RETURN n.name, n.resource_id), not whole nodes."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "cypher": {
                        "type": "string",
                        "description": "The Cypher query to run."
                    }
                },
                "required": ["cypher"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_schema",
            "description": (
                "Returns all node label types with counts and all relationship types with counts. "
                "Call this first when unsure what data is available in the graph."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "refresh_graph",
            "description": (
                "Re-collects all AWS inventory live and rebuilds the graph from scratch. "
                "Use when the user asks for current or up-to-date infrastructure data."
            ),
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    }
]

def _get_cypher(args: dict) -> str:
    # Models occasionally use a slightly different key name
    for key in ("cypher", "query", "cql", "statement"):
        if key in args:
            return args[key]
    # Last resort: take the first string value in the dict
    for v in args.values():
        if isinstance(v, str):
            return v
    return ""


FUNCTIONS = {
    "query_graph": lambda args: query_graph(_get_cypher(args)),
    "get_schema": lambda _: get_schema(),
    "refresh_graph": lambda _: refresh_graph(),
}
