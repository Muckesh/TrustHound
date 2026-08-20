import boto3



# from aws.ec2 import get_ec2_client
from aws.session import get_session


REGION = "ap-southeast-1"

# def get_ec2_client():

#     session = get_session()

#     return session.client(
#         "ec2",
#         region_name=REGION
#     )

def get_ec2_client():
    return boto3.client(
        "ec2",
        region_name=REGION
    )



def list_security_groups():

    ec2 = get_ec2_client()

    paginator = ec2.get_paginator(
        "describe_security_groups"
    )

    security_groups = []

    for page in paginator.paginate():

        for sg in page["SecurityGroups"]:

            security_groups.append({
                "group_id": sg["GroupId"],
                "sg_tag_name": next(
                    (t["Value"] for t in sg.get("Tags", []) if t["Key"] == "Name"),
                    None,
                ),
                "name": sg["GroupName"],
                "vpc_id": sg.get("VpcId"),

                "description": sg.get(
                    "Description"
                ),

                "ingress": sg[
                    "IpPermissions"
                ],

                "egress": sg[
                    "IpPermissionsEgress"
                ]
            })

    return security_groups