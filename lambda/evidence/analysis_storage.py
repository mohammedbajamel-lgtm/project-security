"""Store validated analysis products while excluding raw prompts and responses."""

from evidence.writer import put_json


def store_analysis(s3, bucket, incident_id, kms_key_id, investigation, blast_radius, verification):
    if investigation.get("validation_status") not in {"VALID", "ACCEPTED", "APPROVED"}:
        raise ValueError("only validated investigation reports may be preserved")
    forbidden = {"raw_prompt", "raw_response", "prompt", "model_response"}
    if forbidden & set(investigation):
        raise ValueError("raw model material must not be stored")
    values = {
        "investigation_report.json": investigation,
        "blast_radius_report.json": blast_radius,
        "verification_results.json": verification,
    }
    keys = []
    for filename, value in values.items():
        key = f"evidence/{incident_id}/{filename}"
        put_json(s3, bucket, key, value, kms_key_id)
        keys.append(key)
    return keys
