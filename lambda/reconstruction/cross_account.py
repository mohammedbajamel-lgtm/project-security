"""Cross-account labels derived from ARN account components."""


def _account(arn: str | None) -> str | None:
    parts = (arn or "").split(":")
    return parts[4] if len(parts) > 5 and parts[4] else None


def label(events: list[dict]) -> tuple[list[dict], list[str]]:
    pairs, output = set(), []
    for event in events:
        source = _account(event.get("principal_arn")) or event.get("source_account")
        target = _account(event.get("resource_arn"))
        cross = bool(source and target and source != target)
        if cross:
            pairs.add(f"{source}->{target}")
        output.append(
            {
                **event,
                "cross_account": cross,
                "lateral_movement": cross and event.get("event_name") == "AssumeRole",
            }
        )
    return output, sorted(pairs)
