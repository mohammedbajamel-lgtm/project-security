"""Aggregate append-only remediation and Step Functions history."""

from evidence.writer import put_json


def store_remediation_history(
    s3, audit_table, stepfunctions, bucket, incident_id, execution_arns, kms_key_id
):
    audits = audit_table.scan(
        FilterExpression="incident_id = :id", ExpressionAttributeValues={":id": incident_id}
    ).get("Items", [])
    executions = []
    for execution_arn in execution_arns:
        history = stepfunctions.get_execution_history(
            executionArn=execution_arn, includeExecutionData=True
        ).get("events", [])
        executions.append({"execution_arn": execution_arn, "events": history})
    document = {"incident_id": incident_id, "audit_events": audits, "executions": executions}
    key = f"evidence/{incident_id}/remediation_history.json"
    put_json(s3, bucket, key, document, kms_key_id)
    return {"document": document, "s3_key": key}
