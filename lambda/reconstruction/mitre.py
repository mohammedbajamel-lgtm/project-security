"""Evidence-based MITRE ATT&CK mapping for supported AWS events."""

MAPPINGS = {
    "CreateAccessKey": ("T1098.001", "Account Manipulation: Additional Cloud Roles"),
    "AttachRolePolicy": ("T1098", "Account Manipulation"),
    "AssumeRole": ("T1078.004", "Valid Accounts: Cloud Accounts"),
    "ConsoleLogin": ("T1078.004", "Valid Accounts: Cloud Accounts"),
    "GetObject": ("T1530", "Data from Cloud Storage Object"),
    "StopLogging": ("T1562.008", "Impair Defenses: Disable Cloud Logs"),
}


def map_techniques(timeline: list[dict]) -> list[dict]:
    mapped = {}
    for event in timeline:
        action = event.get("event_name") or event.get("action")
        if action in MAPPINGS:
            technique_id, name = MAPPINGS[action]
            item = mapped.setdefault(
                technique_id,
                {"technique_id": technique_id, "technique_name": name, "evidence_ids": []},
            )
            item["evidence_ids"].append(event.get("evidence_id", event["finding_id"]))
    return list(mapped.values())
