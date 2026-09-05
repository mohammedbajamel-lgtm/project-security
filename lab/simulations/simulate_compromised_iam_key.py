"""Create an immediately-disabled lab key and synthetic suspicious S3 calls."""

import boto3
from common import TAGS, audit, dry_run, guard, name, parser


def main():
    args = parser(__doc__).parse_args()
    guard(args)
    iam, s3 = boto3.client("iam"), boto3.client("s3", region_name=args.region)
    users = [u["UserName"] for u in iam.list_users(PathPrefix="/cloudsec-lab/")["Users"]]
    if args.cleanup:
        for user in users:
            for key in iam.list_access_keys(UserName=user)["AccessKeyMetadata"]:
                iam.delete_access_key(UserName=user, AccessKeyId=key["AccessKeyId"])
            iam.delete_user(UserName=user)
        for bucket in s3.list_buckets()["Buckets"]:
            bucket_name = bucket["Name"]
            if not bucket_name.startswith("cloudsec-lab-suspicious-bucket-"):
                continue
            for item in s3.list_objects_v2(Bucket=bucket_name).get("Contents", []):
                s3.delete_object(Bucket=bucket_name, Key=item["Key"])
            s3.delete_bucket(Bucket=bucket_name)
        return
    if dry_run(
        args,
        [
            "create tagged lab IAM user",
            "create and immediately deactivate key",
            "create/upload/delete lab S3 bucket",
        ],
    ):
        return
    user, bucket = name("compromised-user"), name("suspicious-bucket")
    iam.create_user(
        UserName=user,
        Path="/cloudsec-lab/",
        Tags=[{"Key": x["Key"], "Value": x["Value"]} for x in TAGS],
    )
    key = iam.create_access_key(UserName=user)["AccessKey"]
    iam.update_access_key(UserName=user, AccessKeyId=key["AccessKeyId"], Status="Inactive")
    s3.create_bucket(Bucket=bucket)
    s3.put_object(Bucket=bucket, Key="sensitive-test-only.txt", Body=b"SIMULATION")
    audit("compromised_iam_key", "created_disabled_key", user, args.region)
    print({"access_key_id": key["AccessKeyId"], "bucket": bucket, "secret_discarded": True})


if __name__ == "__main__":
    main()
