import boto3

from aws.session import get_session


REGION = "ap-southeast-1"

# def get_s3_client():

#     session = get_session()

#     return session.client(
#         "s3",
#         region_name=REGION
#     )

def get_s3_client():
    return boto3.client(
        "s3",
        region_name=REGION
    )

def list_s3_buckets():

    s3 = get_s3_client()

    response = s3.list_buckets()

    buckets = []

    for bucket in response["Buckets"]:

        buckets.append({
            "name": bucket["Name"],
            "creation_date": bucket[
                "CreationDate"
            ].isoformat()
        })

    return buckets