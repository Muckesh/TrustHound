import boto3


REGION = "ap-southeast-1"


def get_ec2_client():
    return boto3.client(
        "ec2",
        region_name=REGION
    )

# from aws.session import get_session


# REGION = "eu-west-2"

# def get_ec2_client():

#     session = get_session()

#     return session.client(
#         "ec2",
#         region_name=REGION
#     )   


def list_ec2_instances():
    ec2 = get_ec2_client()

    paginator = ec2.get_paginator("describe_instances")

    instances = []

    for page in paginator.paginate():

        for reservation in page["Reservations"]:

            for instance in reservation["Instances"]:

                instances.append({
                    "instance_id": instance["InstanceId"],
                    "instance_name": next(
                        (t["Value"] for t in instance.get("Tags", []) if t["Key"] == "Name"),
                        None,
                    ),
                    "instance_type": instance["InstanceType"],
                    "state": instance["State"]["Name"],

                    "private_ip": instance.get(
                        "PrivateIpAddress"
                    ),

                    "public_ip": instance.get(
                        "PublicIpAddress"
                    ),

                    "instance_profile_arn": (
                        instance
                        .get("IamInstanceProfile", {})
                        .get("Arn")
                    ),

                    "security_groups": [
                        sg["GroupId"]
                        for sg in instance.get(
                            "SecurityGroups", []
                        )
                    ],

                    "subnet_id": instance.get(
                        "SubnetId"
                    ),

                    "vpc_id": instance.get(
                        "VpcId"
                    ),
                })

    return instances