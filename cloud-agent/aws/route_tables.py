import boto3


REGION = "ap-southeast-1"


def get_ec2_client():
    return boto3.client("ec2", region_name=REGION)


def list_route_tables():

    ec2 = get_ec2_client()

    paginator = ec2.get_paginator("describe_route_tables")

    route_tables = []

    for page in paginator.paginate():

        for rt in page["RouteTables"]:

            associations = rt.get("Associations", [])

            is_main = any(
                assoc.get("Main", False) for assoc in associations
            )

            associated_subnets = [
                assoc["SubnetId"]
                for assoc in associations
                if "SubnetId" in assoc
            ]

            routes = rt.get("Routes", [])

            has_internet_route = any(
                route.get("GatewayId", "").startswith("igw-")
                for route in routes
            )

            has_nat_route = any(
                route.get("NatGatewayId", "").startswith("nat-")
                for route in routes
            )

            simplified_routes = [
                {
                    "destination": (
                        route.get("DestinationCidrBlock")
                        or route.get("DestinationIpv6CidrBlock")
                    ),
                    "target": (
                        route.get("GatewayId")
                        or route.get("NatGatewayId")
                        or route.get("TransitGatewayId")
                        or route.get("VpcPeeringConnectionId")
                        or route.get("NetworkInterfaceId")
                        or "local"
                    ),
                    "state": route.get("State", "active"),
                }
                for route in routes
            ]

            route_tables.append({
                "route_table_id": rt["RouteTableId"],
                "route_table_name": next(
                    (t["Value"] for t in rt.get("Tags", []) if t["Key"] == "Name"),
                    None,
                ),
                "vpc_id": rt["VpcId"],
                "is_main": is_main,
                "associated_subnets": associated_subnets,
                "has_internet_route": has_internet_route,
                "has_nat_route": has_nat_route,
                "routes": simplified_routes,
            })

    return route_tables
