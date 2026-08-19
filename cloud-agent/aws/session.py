# arn:aws:iam::264760299713:role/cloud-security-agent

import boto3


ROLE_ARN = (
    "arn:aws:iam::264760299713:"
    "role/cloud-security-agent"
)


def get_session():

    sts = boto3.client("sts")

    response = sts.assume_role(
        RoleArn=ROLE_ARN,
        RoleSessionName="cloud-security-agent"
    )

    credentials = response["Credentials"]

    return boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"]
    )