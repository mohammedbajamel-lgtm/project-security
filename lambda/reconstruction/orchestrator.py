from reconstruction.attack_stages import classify_timeline
from reconstruction.cross_account import label
from reconstruction.mitre import map_techniques
from reconstruction.timeline import build_timeline


def reconstruct_attack(findings: list[dict]) -> dict:
    timeline = build_timeline(findings)
    labeled, pairs = label(timeline["events"])
    events, anomaly = classify_timeline(labeled)
    stages = list(
        dict.fromkeys(x["attack_stage"] for x in events if x["attack_stage"] != "unknown")
    )
    return {
        "timeline": events,
        "attack_stages_detected": stages,
        "mitre_techniques": map_techniques(events),
        "cross_account_summary": pairs,
        "timeline_gaps": timeline["gap_analysis"],
        "stage_anomaly": anomaly,
        "original_event_count": timeline["original_event_count"],
    }
