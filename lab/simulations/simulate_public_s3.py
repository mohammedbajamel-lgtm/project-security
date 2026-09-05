"""Create a lab-only bucket and attempt a public configuration."""

import boto3
from common import audit, dry_run, guard, name, parser, tag_map


def main():
    args = parser(__doc__).parse_args()
    guard(args)
    s3 = boto3.client("s3", region_name=args.region)
    buckets = [
        b["Name"]
        for b in s3.list_buckets()["Buckets"]
        if b["Name"].startswith("cloudsec-lab-public-")
    ]
    if args.cleanup:
        for bucket in buckets:
            for obj in s3.list_objects_v2(Bucket=bucket).get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
            s3.delete_bucket(Bucket=bucket)
        return
    if dry_run(
        args,
        [
            "create cloudsec-lab bucket",
            "disable bucket public block",
            "set public-read ACL",
            "upload harmless marker",
        ],
    ):
        return
    bucket = name("public")
    s3.create_bucket(Bucket=bucket)
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in tag_map().items()]}
    )
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    )
    s3.put_object(Bucket=bucket, Key="simulation.txt", Body=b"SIMULATION - NO SENSITIVE DATA")
    try:
        s3.put_object_acl(Bucket=bucket, Key="simulation.txt", ACL="public-read")
    except s3.exceptions.ClientError as exc:
        print(f"Public ACL blocked safely: {exc.response['Error']['Code']}")
    audit("public_s3", "public_acl_attempt", bucket, args.region)


if __name__ == "__main__":
    main()
