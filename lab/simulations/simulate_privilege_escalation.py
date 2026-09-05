"""Attach AdministratorAccess to an unassumable lab test role."""

import json

import boto3
from common import TAGS, audit, dry_run, guard, name, parser


def main():
    args = parser(__doc__).parse_args()
    guard(args)
    iam = boto3.client("iam")
    admin = "arn:aws:iam::aws:policy/AdministratorAccess"
    roles = [r["RoleName"] for r in iam.list_roles(PathPrefix="/cloudsec-lab/simulation/")["Roles"]]
    if args.cleanup:
        for role in roles:
            iam.detach_role_policy(RoleName=role, PolicyArn=admin)
            iam.delete_role(RoleName=role)
        return
    if dry_run(
        args,
        [
            "create unassumable lab role",
            "attach AdministratorAccess for detection",
            "never call AssumeRole",
        ],
    ):
        return
    role = name("privilege-role")
    deny_trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(
        RoleName=role,
        Path="/cloudsec-lab/simulation/",
        AssumeRolePolicyDocument=json.dumps(deny_trust),
        Tags=TAGS,
    )
    iam.attach_role_policy(RoleName=role, PolicyArn=admin)
    audit("privilege_escalation", "admin_policy_attached_unassumable_role", role, args.region)


if __name__ == "__main__":
    main()
