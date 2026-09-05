"""Read-only Phase 18 isolation verification."""

import os

import boto3

expected_account = os.environ.get("CLOUDSEC_LAB_ACCOUNT_ID", "")
assert len(expected_account) == 12 and expected_account.isdigit(), (
    "Set CLOUDSEC_LAB_ACCOUNT_ID to the intended 12-digit lab account"
)
identity = boto3.client("sts").get_caller_identity()
assert identity["Account"] == expected_account
print("PASS: expected lab account")

ec2 = boto3.client("ec2", region_name="us-east-1")
peerings = ec2.describe_vpc_peering_connections().get("VpcPeeringConnections", [])
active = [item for item in peerings if item.get("Status", {}).get("Code") != "deleted"]
assert not active
print("PASS: no VPC peering connections")

attachments = ec2.describe_transit_gateway_attachments().get("TransitGatewayAttachments", [])
assert not attachments
print("PASS: no Transit Gateway attachments")

cloudtrail = boto3.client("cloudtrail", region_name="us-east-1")
trail = cloudtrail.describe_trails(trailNameList=["cloudsec-lab-trail"])["trailList"][0]
assert trail["Name"] == "cloudsec-lab-trail"
print("PASS: dedicated lab CloudTrail exists")

detectors = boto3.client("guardduty", region_name="us-east-1").list_detectors()["DetectorIds"]
assert detectors
print("PASS: GuardDuty enabled")

hub = boto3.client("securityhub", region_name="us-east-1").describe_hub()
assert hub["HubArn"]
print("PASS: Security Hub enabled")

user = boto3.client("iam").get_user(UserName="cloudsec-lab-operator")["User"]
boundary = user["PermissionsBoundary"]["PermissionsBoundaryArn"]
assert boundary.endswith("cloudsec-lab-operator-boundary")
print("PASS: restricted lab operator boundary attached")
