"""Deterministic attack-stage rules."""

ORDER = [
    "reconnaissance",
    "initial_access",
    "credential_access",
    "privilege_escalation",
    "defense_evasion",
    "persistence",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact",
]


def classify(event: dict) -> str:
    name, kind = event.get("event_name", ""), event.get("event_type", "")
    if kind in {"UnauthorizedAccess", "UnauthorizedAPI"}:
        return "initial_access"
    if name == "ConsoleLogin" and event.get("source_ip"):
        return "credential_access"
    if name in {"CreateAccessKey", "AttachRolePolicy", "PutUserPolicy"}:
        return "privilege_escalation"
    if name in {"StopLogging", "DeleteTrail", "DisableCloudTrail"}:
        return "defense_evasion"
    if name in {"CreateUser", "PutLoginProfile", "CreateKeyPair"}:
        return "persistence"
    if name == "AssumeRole" and event.get("cross_account"):
        return "lateral_movement"
    if name in {"GetObject", "ListBuckets"} and event.get("sensitive_resource"):
        return "collection"
    if name in {"CreateNatGateway", "AuthorizeSecurityGroupIngress"} and event.get("public_cidr"):
        return "command_and_control"
    if name == "PutBucketPublicAccessBlock" and event.get("public_access_enabled") is True:
        return "exfiltration"
    return "unknown"


def classify_timeline(events: list[dict]) -> tuple[list[dict], bool]:
    result, highest, anomaly = [], -1, False
    for event in events:
        stage = classify(event)
        result.append({**event, "attack_stage": stage})
        if stage != "unknown":
            position = ORDER.index(stage)
            anomaly = anomaly or position < highest
            highest = max(highest, position)
    return result, anomaly
