"""Stop only the dedicated Terraform-managed cloudsec-lab trail."""

import boto3
from common import audit, dry_run, guard, parser


def main():
    args = parser(__doc__).parse_args()
    guard(args)
    ct = boto3.client("cloudtrail", region_name=args.region)
    trail = "cloudsec-lab-trail"
    if args.cleanup:
        ct.start_logging(Name=trail)
        return
    if dry_run(args, [f"stop logging on {trail}", "never touch organization/dev trails"]):
        return
    if not any(
        t["Name"] == trail for t in ct.describe_trails(includeShadowTrails=False)["trailList"]
    ):
        raise SystemExit("lab trail not found")
    ct.stop_logging(Name=trail)
    audit("cloudtrail_tamper", "stopped_lab_trail", trail, args.region)


if __name__ == "__main__":
    main()
