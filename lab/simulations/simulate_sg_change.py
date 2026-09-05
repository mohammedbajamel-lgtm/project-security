"""Create a lab security group and expose test-only SSH ingress."""

import boto3
from common import audit, dry_run, guard, name, parser, tag_map


def main():
    args = parser(__doc__).parse_args()
    guard(args)
    ec2 = boto3.client("ec2", region_name=args.region)
    groups = ec2.describe_security_groups(
        Filters=[
            {"Name": "tag:Environment", "Values": ["lab"]},
            {"Name": "group-name", "Values": ["cloudsec-lab-sg-*"]},
        ]
    )["SecurityGroups"]
    reservations = ec2.describe_instances(
        Filters=[
            {"Name": "tag:Simulation", "Values": ["sg-change"]},
            {"Name": "instance-state-name", "Values": ["pending", "running", "stopped"]},
        ]
    )["Reservations"]
    if args.cleanup:
        instance_ids = [item["InstanceId"] for row in reservations for item in row["Instances"]]
        if instance_ids:
            ec2.terminate_instances(InstanceIds=instance_ids)
            ec2.get_waiter("instance_terminated").wait(InstanceIds=instance_ids)
        for g in groups:
            try:
                ec2.delete_security_group(GroupId=g["GroupId"])
            except ec2.exceptions.ClientError:
                pass
        return
    if dry_run(
        args,
        ["create SG in cloudsec-lab VPC", "launch isolated t3.micro", "authorize 0.0.0.0/0 TCP/22"],
    ):
        return
    vpc = ec2.describe_vpcs(Filters=[{"Name": "tag:Name", "Values": ["cloudsec-lab-vpc"]}])["Vpcs"][
        0
    ]
    group = name("sg")
    gid = ec2.create_security_group(
        GroupName=group,
        Description="SIMULATION ONLY",
        VpcId=vpc["VpcId"],
        TagSpecifications=[
            {
                "ResourceType": "security-group",
                "Tags": [{"Key": k, "Value": v} for k, v in tag_map().items()],
            }
        ],
    )["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=gid,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "SIMULATION ONLY"}],
            }
        ],
    )
    subnet = ec2.describe_subnets(
        Filters=[{"Name": "tag:Name", "Values": ["cloudsec-lab-isolated-subnet"]}]
    )["Subnets"][0]
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-2023*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    ami = sorted(images, key=lambda item: item["CreationDate"], reverse=True)[0]["ImageId"]
    result = ec2.run_instances(
        ImageId=ami,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet["SubnetId"],
        SecurityGroupIds=[gid],
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [
                    {"Key": key, "Value": value}
                    for key, value in tag_map({"Simulation": "sg-change"}).items()
                ],
            }
        ],
    )
    print({"instance_id": result["Instances"][0]["InstanceId"], "group_id": gid})
    audit("sg_change", "opened_test_ssh", gid, args.region)


if __name__ == "__main__":
    main()
