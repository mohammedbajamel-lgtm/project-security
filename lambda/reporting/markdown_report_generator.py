"""Render the canonical JSON report as readable Markdown."""


def _table(headers, rows):
    output = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    output.extend(
        "| " + " | ".join(str(cell).replace("|", "\\|") for cell in row) + " |" for row in rows
    )
    return "\n".join(output)


def generate_markdown_report(report):
    timeline = [
        [
            item.get("time", ""),
            item.get("event", ""),
            item.get("attack_stage", ""),
            item.get("evidence_id", ""),
        ]
        for item in report.get("timeline", [])
    ]
    actions = [
        [item.get("timestamp", ""), item.get("action", ""), item.get("status", "")]
        for item in report.get("actions_taken", [])
    ]
    lines = [
        f"# Incident Report: {report['incident_id']}",
        f"Generated: {report['generated_at']}  ",
        f"Platform version: {report['platform_version']}",
        "## Executive Summary",
        report.get("executive_summary", "Not available."),
        "## Timeline",
        _table(["Time", "Event", "Attack Stage", "Evidence ID"], timeline),
        "## Root Cause Analysis",
        report.get("root_cause", "Not established."),
        "## Attack Stages and MITRE Techniques",
        ", ".join(report.get("mitre_attack_techniques", [])) or "None recorded.",
        "## Affected Principals",
        "\n".join(f"- {value}" for value in report.get("affected_principals", []))
        or "None recorded.",
        "## Affected Resources",
        "\n".join(f"- {value}" for value in report.get("affected_resources", []))
        or "None recorded.",
        "## Blast Radius",
        str(report.get("blast_radius") or "Not available."),
        "## Actions Taken",
        _table(["Timestamp", "Action", "Status"], actions),
        "## Evidence",
        str(report.get("evidence") or "Not available."),
        "## Verification Results",
        str(report.get("verification") or "Not available."),
        "## Recommendations",
        "\n".join(f"- {value}" for value in report.get("recommendations", [])) or "None recorded.",
    ]
    return "\n\n".join(lines) + "\n"
