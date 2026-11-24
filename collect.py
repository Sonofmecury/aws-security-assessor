"""Collect read-only inventory from one explicit AWS account and region."""
import argparse
import json
from datetime import datetime, timezone


def paginate(client, operation, field, **arguments):
    for page in client.get_paginator(operation).paginate(**arguments):
        yield from page[field]


def collect(session, account, region):
    from botocore.exceptions import BotoCoreError, ClientError

    sts = session.client("sts", region_name=region)
    if sts.get_caller_identity()["Account"] != account:
        raise ValueError("Credential account and selected account do not match")

    iam = session.client("iam")
    ec2 = session.client("ec2", region_name=region)
    s3 = session.client("s3", region_name=region)
    result = {"scope": {"account": account, "region": region},
              "collected_at": datetime.now(timezone.utc).isoformat(), "coverage": {}}

    def identify(row, key):
        return {**row, "id": row[key]}

    def policies():
        for item in paginate(iam, "list_policies", "Policies", Scope="Local"):
            version = iam.get_policy_version(PolicyArn=item["Arn"], VersionId=item["DefaultVersionId"])
            yield {"id": item["Arn"], "PolicyDocument": version["PolicyVersion"]["Document"]}

    def bucket_property(operation, bucket, field, absent, **kwargs):
        try:
            return getattr(s3, operation)(Bucket=bucket, ExpectedBucketOwner=account, **kwargs)[field]
        except ClientError as error:
            if error.response["Error"]["Code"] in absent:
                return absent[error.response["Error"]["Code"]]
            return {}

    def buckets():
        for item in paginate(s3, "list_buckets", "Buckets", BucketRegion=region):
            name = item["Name"]
            yield {"id": name,
                   **bucket_property("get_bucket_policy_status", name, "PolicyStatus",
                                     {"NoSuchBucketPolicy": {"IsPublic": False}}),
                   **bucket_property("get_public_access_block", name, "PublicAccessBlockConfiguration",
                                     {"NoSuchPublicAccessBlockConfiguration": dict.fromkeys(
                                         ["BlockPublicAcls", "IgnorePublicAcls",
                                          "BlockPublicPolicy", "RestrictPublicBuckets"], False)}),
                   "Versioning": s3.get_bucket_versioning(Bucket=name, ExpectedBucketOwner=account).get("Status", "Off")}

    sections = {
        "account": lambda: [{"id": account, **iam.get_account_summary()["SummaryMap"]}],
        "iam_policies": policies,
        "groups": lambda: (identify(row, "GroupId") for row in paginate(ec2, "describe_security_groups", "SecurityGroups")),
        "instances": lambda: (identify(row, "InstanceId")
                               for reservation in paginate(ec2, "describe_instances", "Reservations")
                               for row in reservation["Instances"]),
        "volumes": lambda: (identify(row, "VolumeId") for row in paginate(ec2, "describe_volumes", "Volumes")),
        "buckets": buckets,
    }
    for section, read in sections.items():
        try:
            result[section] = list(read())
            result["coverage"][section] = "collected"
        except ClientError as error:
            result["coverage"][section] = error.response["Error"]["Code"]
        except (BotoCoreError, KeyError, ValueError) as error:
            result["coverage"][section] = type(error).__name__
    return result


def main():
    import boto3
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--account", required=True)
    parser.add_argument("--region", required=True)
    args = parser.parse_args()
    if len(args.account) != 12 or not args.account.isascii() or not args.account.isdigit():
        parser.error("--account must be a 12-digit AWS account ID")
    print(json.dumps(collect(boto3.Session(profile_name=args.profile), args.account, args.region),
                     indent=2, default=str))


if __name__ == "__main__":
    main()
