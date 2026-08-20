import os

from neo4j import GraphDatabase


class Neo4jCloudGraph:
    def __init__(self, uri, username, password):
        self.driver = GraphDatabase.driver(uri, auth=(username, password))

    def close(self):
        self.driver.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def clear(self):
        with self.driver.session() as session:
            session.run("MATCH (n) DETACH DELETE n")

    def node_count(self):
        with self.driver.session() as session:
            return session.run(
                "MATCH (n) RETURN count(n) AS c"
            ).single()["c"]

    def edge_count(self):
        with self.driver.session() as session:
            return session.run(
                "MATCH ()-[r]->() RETURN count(r) AS c"
            ).single()["c"]

    def query(self, cypher, **params):
        with self.driver.session() as session:
            return list(session.run(cypher, **params))

    def _build_vpcs(self, session, vpcs):
        for vpc in vpcs:
            session.run(
                "MERGE (v:VPC {resource_id: $id}) "
                "SET v.name = $name, v.cidr = $cidr, v.state = $state, v.is_default = $is_default",
                id=vpc["vpc_id"],
                name=vpc.get("vpc_name"),
                cidr=vpc["cidr"],
                state=vpc["state"],
                is_default=vpc["is_default"],
            )

    def _build_subnets(self, session, subnets):
        for subnet in subnets:
            session.run(
                "MERGE (s:Subnet {resource_id: $id}) "
                "SET s.name = $name, s.cidr = $cidr, s.availability_zone = $az, "
                "s.state = $state, s.public_ip_on_launch = $pub "
                "WITH s "
                "MATCH (v:VPC {resource_id: $vpc_id}) "
                "MERGE (s)-[:BELONGS_TO]->(v)",
                id=subnet["subnet_id"],
                name=subnet.get("subnet_name"),
                cidr=subnet["cidr"],
                az=subnet["availability_zone"],
                state=subnet["state"],
                pub=subnet["map_public_ip_on_launch"],
                vpc_id=subnet["vpc_id"],
            )

    def _build_security_groups(self, session, security_groups):
        for sg in security_groups:
            session.run(
                "MERGE (sg:SecurityGroup {resource_id: $id}) "
                "SET sg.name = $name, sg.description = $desc",
                id=sg["group_id"],
                name=sg.get("sg_tag_name"),
                desc=sg["description"],
            )
            if sg["vpc_id"]:
                session.run(
                    "MATCH (sg:SecurityGroup {resource_id: $sg_id}) "
                    "MATCH (v:VPC {resource_id: $vpc_id}) "
                    "MERGE (sg)-[:BELONGS_TO]->(v)",
                    sg_id=sg["group_id"],
                    vpc_id=sg["vpc_id"],
                )

    def _build_roles(self, session, roles):
        for role in roles:
            session.run(
                "MERGE (r:IAMRole {resource_id: $id}) "
                "SET r.name = $name, r.arn = $arn, r.create_date = $create_date",
                id=role["role_name"],
                name=role["role_name"],
                arn=role["arn"],
                create_date=role["create_date"],
            )

    def _build_instances(self, session, instances):
        for inst in instances:
            session.run(
                "MERGE (e:EC2Instance {resource_id: $id}) "
                "SET e.name = $name, e.instance_type = $itype, e.state = $state, "
                "e.private_ip = $priv, e.public_ip = $pub",
                id=inst["instance_id"],
                name=inst.get("instance_name"),
                itype=inst["instance_type"],
                state=inst["state"],
                priv=inst["private_ip"],
                pub=inst["public_ip"],
            )
            if inst["subnet_id"]:
                session.run(
                    "MATCH (e:EC2Instance {resource_id: $ec2_id}) "
                    "MATCH (s:Subnet {resource_id: $subnet_id}) "
                    "MERGE (e)-[:LOCATED_IN]->(s)",
                    ec2_id=inst["instance_id"],
                    subnet_id=inst["subnet_id"],
                )
            for sg_id in inst["security_groups"]:
                session.run(
                    "MATCH (e:EC2Instance {resource_id: $ec2_id}) "
                    "MATCH (sg:SecurityGroup {resource_id: $sg_id}) "
                    "MERGE (e)-[:USES_SECURITY_GROUP]->(sg)",
                    ec2_id=inst["instance_id"],
                    sg_id=sg_id,
                )
            if inst.get("instance_profile_arn"):
                role_name = inst["instance_profile_arn"].split("/")[-1]
                session.run(
                    "MATCH (e:EC2Instance {resource_id: $ec2_id}) "
                    "MATCH (r:IAMRole {resource_id: $role_name}) "
                    "MERGE (e)-[:ASSUMES_ROLE]->(r)",
                    ec2_id=inst["instance_id"],
                    role_name=role_name,
                )

    def _build_buckets(self, session, buckets):
        for bucket in buckets:
            session.run(
                "MERGE (b:S3Bucket {resource_id: $id}) "
                "SET b.name = $name, b.creation_date = $creation_date",
                id=bucket["name"],
                name=bucket["name"],
                creation_date=bucket["creation_date"],
            )

    def _build_sg_rules(self, session, security_groups):
        for sg in security_groups:
            sg_id = sg["group_id"]

            for direction, rules in [
                ("ingress", sg["ingress"]),
                ("egress", sg["egress"]),
            ]:
                for rule_idx, rule in enumerate(rules):
                    protocol = rule.get("IpProtocol", "-1")
                    from_port = rule.get("FromPort")
                    to_port = rule.get("ToPort")

                    sub_idx = 0

                    for ip_range in rule.get("IpRanges", []):
                        rule_id = f"{sg_id}:{direction}:{rule_idx}:{sub_idx}"
                        session.run(
                            "MERGE (r:SGRule {resource_id: $id}) "
                            "SET r.direction = $dir, r.protocol = $proto, "
                            "r.from_port = $from_port, r.to_port = $to_port, "
                            "r.cidr = $cidr, r.description = $desc "
                            "WITH r "
                            "MATCH (sg:SecurityGroup {resource_id: $sg_id}) "
                            "MERGE (sg)-[:HAS_RULE]->(r)",
                            id=rule_id,
                            dir=direction,
                            proto=protocol,
                            from_port=from_port,
                            to_port=to_port,
                            cidr=ip_range.get("CidrIp"),
                            desc=ip_range.get("Description"),
                            sg_id=sg_id,
                        )
                        sub_idx += 1

                    for ip_range in rule.get("Ipv6Ranges", []):
                        rule_id = f"{sg_id}:{direction}:{rule_idx}:{sub_idx}"
                        session.run(
                            "MERGE (r:SGRule {resource_id: $id}) "
                            "SET r.direction = $dir, r.protocol = $proto, "
                            "r.from_port = $from_port, r.to_port = $to_port, "
                            "r.cidr = $cidr, r.description = $desc "
                            "WITH r "
                            "MATCH (sg:SecurityGroup {resource_id: $sg_id}) "
                            "MERGE (sg)-[:HAS_RULE]->(r)",
                            id=rule_id,
                            dir=direction,
                            proto=protocol,
                            from_port=from_port,
                            to_port=to_port,
                            cidr=ip_range.get("CidrIpv6"),
                            desc=ip_range.get("Description"),
                            sg_id=sg_id,
                        )
                        sub_idx += 1

                    for group_pair in rule.get("UserIdGroupPairs", []):
                        source_sg_id = group_pair.get("GroupId")
                        rule_id = f"{sg_id}:{direction}:{rule_idx}:{sub_idx}"
                        session.run(
                            "MERGE (r:SGRule {resource_id: $id}) "
                            "SET r.direction = $dir, r.protocol = $proto, "
                            "r.from_port = $from_port, r.to_port = $to_port, "
                            "r.source_sg = $source_sg, r.description = $desc "
                            "WITH r "
                            "MATCH (sg:SecurityGroup {resource_id: $sg_id}) "
                            "MERGE (sg)-[:HAS_RULE]->(r)",
                            id=rule_id,
                            dir=direction,
                            proto=protocol,
                            from_port=from_port,
                            to_port=to_port,
                            source_sg=source_sg_id,
                            desc=group_pair.get("Description"),
                            sg_id=sg_id,
                        )
                        # Also link the rule to the source SG it references
                        if source_sg_id:
                            session.run(
                                "MATCH (r:SGRule {resource_id: $rule_id}) "
                                "MATCH (src:SecurityGroup {resource_id: $src_id}) "
                                "MERGE (r)-[:REFERENCES_SG]->(src)",
                                rule_id=rule_id,
                                src_id=source_sg_id,
                            )
                        sub_idx += 1

    def _build_route_tables(self, session, route_tables):
        import json

        for rt in route_tables:
            session.run(
                "MERGE (r:RouteTable {resource_id: $id}) "
                "SET r.name = $name, r.is_main = $is_main, "
                "r.has_internet_route = $has_igw, r.has_nat_route = $has_nat, "
                "r.routes = $routes "
                "WITH r "
                "MATCH (v:VPC {resource_id: $vpc_id}) "
                "MERGE (r)-[:BELONGS_TO]->(v)",
                id=rt["route_table_id"],
                name=rt.get("route_table_name"),
                is_main=rt["is_main"],
                has_igw=rt["has_internet_route"],
                has_nat=rt["has_nat_route"],
                routes=json.dumps(rt["routes"]),
                vpc_id=rt["vpc_id"],
            )
            for subnet_id in rt["associated_subnets"]:
                session.run(
                    "MATCH (s:Subnet {resource_id: $subnet_id}) "
                    "MATCH (r:RouteTable {resource_id: $rt_id}) "
                    "MERGE (s)-[:USES_ROUTE_TABLE]->(r)",
                    subnet_id=subnet_id,
                    rt_id=rt["route_table_id"],
                )

    def build(self, vpcs, subnets, instances, security_groups, roles, buckets, route_tables):
        with self.driver.session() as session:
            self._build_vpcs(session, vpcs)
            self._build_subnets(session, subnets)
            self._build_security_groups(session, security_groups)
            self._build_sg_rules(session, security_groups)
            self._build_roles(session, roles)
            self._build_instances(session, instances)
            self._build_buckets(session, buckets)
            self._build_route_tables(session, route_tables)


def build_cloud_graph(vpcs, subnets, instances, security_groups, roles, buckets, route_tables):
    uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    username = os.environ.get("NEO4J_USERNAME", "neo4j")
    password = os.environ.get("NEO4J_PASSWORD", "hackathon")

    graph = Neo4jCloudGraph(uri, username, password)
    graph.clear()
    graph.build(
        vpcs=vpcs,
        subnets=subnets,
        instances=instances,
        security_groups=security_groups,
        roles=roles,
        buckets=buckets,
        route_tables=route_tables,
    )
    return graph
