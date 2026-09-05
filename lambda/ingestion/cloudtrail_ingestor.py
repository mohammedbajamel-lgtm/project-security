"""Compatibility entrypoint for the CloudTrail parser."""

from cloudtrail_parser import lambda_handler, normalize_record

__all__ = ["lambda_handler", "normalize_record"]
