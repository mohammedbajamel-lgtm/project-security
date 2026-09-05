"""Generate a concise, non-sensitive leadership summary."""

import re

SENSITIVE = re.compile(
    r"arn:aws:[^\s,;]+|\b(?:\d{1,3}\.){3}\d{1,3}\b|\bAKIA[A-Z0-9]{12,}\b",
    re.IGNORECASE,
)


def _clean(value):
    return SENSITIVE.sub("[REDACTED]", str(value or "unspecified"))


def generate_executive_summary(incident):
    recommendations = incident.get("recommendations") or ["Review monitoring and access controls"]
    sentences = [
        f"A {_clean(incident.get('severity', 'security'))} security incident was detected.",
        "The activity was identified through "
        f"{_clean(incident.get('detection_source', 'security telemetry'))}.",
        "The assessed business impact was "
        f"{_clean(incident.get('business_impact', 'limited pending review'))}.",
        "The response team performed "
        f"{_clean(incident.get('action_summary', 'containment and verification'))}.",
        f"The incident is currently {_clean(incident.get('status', 'under review')).lower()}.",
    ]
    sentences.extend(f"Recommendation: {_clean(item)}." for item in recommendations[:3])
    return " ".join(sentences[:10])
