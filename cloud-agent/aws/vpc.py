import boto3

from aws.session import get_session


REGION = "ap-southeast-1"

# def get_ec2_client():

#     session = get_session()

#     return session.client(
#         "ec2",
#         region_name=REGION
#     )

# def get_s3_client():

#     session = get_session()

#     return session.client(
#         "s3",
#         region_name=REGION
#     )

def get_ec2_client():
    return boto3.client(
        "ec2",
        region_name=REGION
    )

def get_s3_client():
    return boto3.client(
        "s3",
        region_name=REGION
    )

def list_vpcs():

    ec2 = get_ec2_client()

    response = ec2.describe_vpcs()

    vpcs = []

    for vpc in response["Vpcs"]:

        vpcs.append({
            "vpc_id": vpc["VpcId"],
            "vpc_name": next(
                (t["Value"] for t in vpc.get("Tags", []) if t["Key"] == "Name"),
                None,
            ),
            "cidr": vpc["CidrBlock"],
            "state": vpc["State"],
            "is_default": vpc.get("IsDefault", False)
        })

    return vpcs


def list_subnets():

    ec2 = get_ec2_client()

    paginator = ec2.get_paginator(
        "describe_subnets"
    )

    subnets = []

    for page in paginator.paginate():

        for subnet in page["Subnets"]:

            subnets.append({
                "subnet_id": subnet["SubnetId"],
                "subnet_name": next(
                    (t["Value"] for t in subnet.get("Tags", []) if t["Key"] == "Name"),
                    None,
                ),
                "vpc_id": subnet["VpcId"],
                "cidr": subnet["CidrBlock"],
                "availability_zone": subnet[
                    "AvailabilityZone"
                ],
                "available_ip_count": subnet[
                    "AvailableIpAddressCount"
                ],
                "state": subnet["State"],
                "map_public_ip_on_launch": subnet[
                    "MapPublicIpOnLaunch"
                ]
            })

    return subnets