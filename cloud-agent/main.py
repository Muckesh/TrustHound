from aws.ec2 import list_ec2_instances
from aws.iam import list_iam_roles
from aws.route_tables import list_route_tables
from aws.s3 import list_s3_buckets
from aws.vpc import list_vpcs, list_subnets
from aws.security_groups import list_security_groups

from graph.builder import build_cloud_graph


def main():

    print("Collecting AWS inventory...")

    vpcs = list_vpcs()

    print(f"VPCs: {len(vpcs)}")

    subnets = list_subnets()

    print(f"Subnets: {len(subnets)}")

    instances = list_ec2_instances()

    print(f"EC2 instances: {len(instances)}")

    security_groups = list_security_groups()

    print(
        f"Security groups: "
        f"{len(security_groups)}"
    )

    roles = list_iam_roles()

    print(f"IAM roles: {len(roles)}")

    buckets = list_s3_buckets()

    print(f"S3 buckets: {len(buckets)}")

    route_tables = list_route_tables()

    print(f"Route tables: {len(route_tables)}")

    print("\nBuilding graph...")

    with build_cloud_graph(
        vpcs=vpcs,
        subnets=subnets,
        instances=instances,
        security_groups=security_groups,
        roles=roles,
        buckets=buckets,
        route_tables=route_tables,
    ) as graph:

        print("\nGraph created:")

        print(f"Nodes: {graph.node_count()}")

        print(f"Edges: {graph.edge_count()}")

        print("\nNodes:")

        for record in graph.query(
            "MATCH (n) RETURN labels(n) AS labels, "
            "n.resource_id AS id, properties(n) AS props "
            "ORDER BY labels(n), n.resource_id"
        ):
            print(record["labels"], record["id"], dict(record["props"]))

        print("\nEdges:")

        for record in graph.query(
            "MATCH (a)-[r]->(b) "
            "RETURN a.resource_id AS source, type(r) AS rel, b.resource_id AS target "
            "ORDER BY type(r), a.resource_id"
        ):
            print(
                record["source"],
                "-->",
                record["rel"],
                "-->",
                record["target"],
            )


if __name__ == "__main__":
    main()
