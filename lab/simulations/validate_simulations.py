"""Validate the six explicit Phase 18 Security Hub practice findings."""

import time

import boto3
from common import LAB_ACCOUNT, guard, parser

SCENARIOS = {
    "compromised_iam_key": "CreateAccessKey",
    "sg_change": "AuthorizeSecurityGroupIngress",
    "public_s3": "PutPublicAccessBlock",
    "ec2_compromise": "RunInstances",
    "cloudtrail_tamper": "StopLogging",
    "privilege_escalation": "AttachRolePolicy",
}


def main():
    args = parser(__doc__).parse_args()
    guard(args)
    securityhub = boto3.client("securityhub", region_name=args.region)
    product_arn = f"arn:aws:securityhub:{args.region}:{LAB_ACCOUNT}:product/{LAB_ACCOUNT}/default"
    found = {}
    for attempt in range(18):
        for scenario in SCENARIOS:
            if scenario in found:
                continue
            result = securityhub.get_findings(
                Filters={
                    "ProductArn": [{"Value": product_arn, "Comparison": "EQUALS"}],
                    "GeneratorId": [{"Value": f"cloudsec-lab/{scenario}", "Comparison": "EQUALS"}],
                    "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                },
                MaxResults=10,
            )
            if result["Findings"]:
                found[scenario] = result["Findings"]
        if len(found) == len(SCENARIOS):
            break
        if attempt < 17:
            time.sleep(10)
    failed = []
    for scenario in SCENARIOS:
        findings = found.get(scenario, [])
        print(f"{'PASS' if findings else 'FAIL'}: {scenario}")
        for finding in findings[:1]:
            print(f"  finding_id={finding['Id']}")
        if not findings:
            failed.append(scenario)
    if failed:
        raise SystemExit(f"Missing simulation evidence: {', '.join(failed)}")


if __name__ == "__main__":
    main()
