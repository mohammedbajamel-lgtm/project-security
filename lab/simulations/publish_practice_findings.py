"""Publish six clearly labeled synthetic findings after real practice simulations."""

from common import guard, parser, publish_practice_finding
from validate_simulations import SCENARIOS


def main():
    args = parser(__doc__).parse_args()
    guard(args)
    for scenario in SCENARIOS:
        publish_practice_finding(scenario, args.region)


if __name__ == "__main__":
    main()
