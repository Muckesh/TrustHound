import boto3

from aws.session import get_session


REGION = "ap-southeast-1"

# def get_ec2_client():

#     session = get_session()

#     return session.client(
#         "ec2",
#         region_name=REGION
#     )


# def get_iam_client():
#     session = get_session()
#     return session.client(
#         "iam",
#         region_name=REGION
#     )

def get_ec2_client():
    return boto3.client(
        "ec2",
        region_name=REGION
    )

def get_iam_client():
    return boto3.client(
        "iam",
        region_name=REGION
    )

def list_iam_roles():

    iam = get_iam_client()

    paginator = iam.get_paginator(
        "list_roles"
    )

    roles = []

    for page in paginator.paginate():

        for role in page["Roles"]:

            roles.append({
                "role_name": role["RoleName"],
                "role_id": role["RoleId"],
                "arn": role["Arn"],
                "create_date": role[
                    "CreateDate"
                ].isoformat(),

                "assume_role_policy": role[
                    "AssumeRolePolicyDocument"
                ]
            })

    return roles