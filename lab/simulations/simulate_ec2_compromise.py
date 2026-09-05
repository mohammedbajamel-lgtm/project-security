"""Create a short-lived isolated EC2 instance and discarded key pair."""

import boto3
from common import audit, dry_run, guard, name, parser, tag_map


def main():
    args = parser(__doc__).parse_args()
    guard(args)
    ec2 = boto3.client("ec2", region_name=args.region)
    instances = ec2.describe_instances(
        Filters=[
            {"Name": "tag:Simulation", "Values": ["ec2-compromise"]},
            {"Name": "instance-state-name", "Values": ["pending", "running", "stopped"]},
        ]
    )["Reservations"]
    keys = [
        k["KeyName"]
        for k in ec2.describe_key_pairs(
            Filters=[{"Name": "key-name", "Values": ["cloudsec-lab-key-*"]}]
        )["KeyPairs"]
    ]
    if args.cleanup:
        ids = [i["InstanceId"] for r in instances for i in r["Instances"]]
        if ids:
            ec2.terminate_instances(InstanceIds=ids)
        for key in keys:
            ec2.delete_key_pair(KeyName=key)
        return
    if dry_run(
        args,
        [
            "create/discard EC2 key material",
            "launch t3.micro in isolated subnet",
            "record simulated unauthorized SSH",
        ],
    ):
        return
    subnet = ec2.describe_subnets(
        Filters=[{"Name": "tag:Name", "Values": ["cloudsec-lab-isolated-subnet"]}]
    )["Subnets"][0]
    image = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-2023*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    ami = sorted(image, key=lambda x: x["CreationDate"], reverse=True)[0]["ImageId"]
    key = name("key")
    ec2.create_key_pair(
        KeyName=key,
        TagSpecifications=[
            {
                "ResourceType": "key-pair",
                "Tags": [{"Key": k, "Value": v} for k, v in tag_map().items()],
            }
        ],
    )
    tags = tag_map({"Simulation": "ec2-compromise", "Name": name("instance")})
    response = ec2.run_instances(
        ImageId=ami,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet["SubnetId"],
        KeyName=key,
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": [{"Key": k, "Value": v} for k, v in tags.items()]}
        ],
    )
    iid = response["Instances"][0]["InstanceId"]
    audit("ec2_compromise", "unauthorized_ssh_simulated", iid, args.region)
    print({"instance_id": iid, "key_name": key, "private_key_discarded": True})


if __name__ == "__main__":
    main()
