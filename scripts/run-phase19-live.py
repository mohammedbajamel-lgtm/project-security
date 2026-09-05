"""Run bounded Phase 19 live safety checkpoints in the isolated lab account."""

from __future__ import annotations

import argparse
import json
import os
import time
import uuid
from datetime import UTC, datetime
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import boto3

LAB_ACCOUNT = os.environ.get("CLOUDSEC_LAB_ACCOUNT_ID", "")
PREFIX = "/cloudsec/lab/e2e/"


def load_config(session):
    if len(LAB_ACCOUNT) != 12 or not LAB_ACCOUNT.isdigit():
        raise RuntimeError("Set CLOUDSEC_LAB_ACCOUNT_ID to the intended 12-digit lab account")
    values = {}
    paginator = session.client("ssm").get_paginator("get_parameters_by_path")
    for page in paginator.paginate(Path=PREFIX, Recursive=True, WithDecryption=True):
        for item in page["Parameters"]:
            values[item["Name"].removeprefix(PREFIX)] = item["Value"]
    if values.get("account_id") != LAB_ACCOUNT or values.get("resource_prefix") != "cloudsec-lab":
        raise RuntimeError("Refusing to run outside the isolated cloudsec-lab environment")
    return values


def invoke_json(client, function_name, payload):
    response = client.invoke(
        FunctionName=function_name,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload).encode(),
    )
    body = json.loads(response["Payload"].read())
    if response.get("FunctionError"):
        raise RuntimeError(f"{function_name} failed: {body}")
    return body


def wait_execution(stepfunctions, execution_arn, timeout=180):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = stepfunctions.describe_execution(executionArn=execution_arn)
        if result["status"] not in {"RUNNING"}:
            return result
        time.sleep(2)
    raise TimeoutError("Step Functions execution exceeded three minutes")


def wait_execution_for_decision(stepfunctions, state_machine_arn, decision_id, started_after):
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        page = stepfunctions.list_executions(stateMachineArn=state_machine_arn, maxResults=50)
        for summary in page.get("executions", []):
            if summary["startDate"] < started_after:
                continue
            execution = stepfunctions.describe_execution(executionArn=summary["executionArn"])
            if json.loads(execution["input"]).get("decision_id") == decision_id:
                return execution["executionArn"]
        time.sleep(2)
    raise TimeoutError(f"No Step Functions execution found for decision {decision_id}")


def wait_incident(table, incident_id, event_time, expected, timeout=180):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        item = table.get_item(
            Key={"incident_id": incident_id, "event_time": event_time}, ConsistentRead=True
        ).get("Item")
        if item and item.get("status") in expected:
            return item
        time.sleep(2)
    raise TimeoutError(f"Incident {incident_id} did not reach {sorted(expected)}")


def wait_pending(table, decision_id, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        items = table.query(
            KeyConditionExpression="decision_id = :decision_id",
            ExpressionAttributeValues={":decision_id": decision_id},
            ConsistentRead=True,
        ).get("Items", [])
        if items:
            return items[0]
        time.sleep(2)
    raise TimeoutError(f"Approval decision {decision_id} was not registered")


def api_json(url, token, method="GET", body=None):
    if not url.startswith("https://"):
        raise RuntimeError("Refusing non-HTTPS approval API URL")
    request = Request(  # noqa: S310 - URL is restricted to HTTPS above.
        url,
        data=json.dumps(body).encode() if body is not None else None,
        method=method,
        headers={"Authorization": token, "Content-Type": "application/json"},
    )
    try:
        with urlopen(request, timeout=30) as response:  # noqa: S310
            return response.status, json.loads(response.read() or b"{}")
    except HTTPError as exc:
        raise RuntimeError(f"Approval API returned {exc.code}: {exc.read().decode()}") from exc


def create_test_approver(session, config, run_id):
    cognito = session.client("cognito-idp")
    username = f"phase19-{run_id}"
    password = f"Phase19!Aa-{uuid.uuid4().hex[:12]}"
    cognito.admin_create_user(
        UserPoolId=config["approval_user_pool_id"],
        Username=username,
        TemporaryPassword=password,
        MessageAction="SUPPRESS",
    )
    cognito.admin_set_user_password(
        UserPoolId=config["approval_user_pool_id"],
        Username=username,
        Password=password,
        Permanent=True,
    )
    cognito.admin_add_user_to_group(
        UserPoolId=config["approval_user_pool_id"],
        Username=username,
        GroupName="cloudsec_approver",
    )
    auth = cognito.admin_initiate_auth(
        UserPoolId=config["approval_user_pool_id"],
        ClientId=config["approval_client_id"],
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    return username, auth["AuthenticationResult"]["IdToken"]


def public_s3_checkpoint(session, config, run_id, token):
    s3 = session.client("s3")
    lambdas = session.client("lambda")
    stepfunctions = session.client("stepfunctions")
    incidents = session.resource("dynamodb").Table(config["incidents_table"])
    bucket = f"cloudsec-lab-e2e-public-{run_id}"
    decision_id = None
    pending = None
    execution_arn = None
    event_time = datetime.now(UTC).isoformat()
    incident_id = f"e2e-s3-{run_id}"
    try:
        s3.create_bucket(Bucket=bucket)
        s3.put_bucket_tagging(
            Bucket=bucket,
            Tagging={
                "TagSet": [
                    {"Key": "Environment", "Value": "lab"},
                    {"Key": "ManagedBy", "Value": "phase19-e2e"},
                    {"Key": "E2ERunId", "Value": run_id},
                ]
            },
        )
        s3.put_public_access_block(
            Bucket=bucket,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
        )
        incident = {
            "incident_id": incident_id,
            "event_time": event_time,
            "finding_id": f"e2e-finding-s3-{run_id}",
            "severity": "P3",
            "status": "REMEDIATING",
            "created_at": event_time,
        }
        incidents.put_item(Item=incident)
        report = {
            "incident_id": incident_id,
            "finding_type": "PublicS3Bucket",
            "validation_status": "APPROVED",
            "affected_principals": [],
            "affected_resources": [{"arn": f"arn:aws:s3:::{bucket}"}],
            "evidence_citations": [{"evidence_id": "e2e", "quote": bucket}],
            "blast_radius": {"risk_score": 1},
            "recommended_actions": [
                {
                    "action": "block_s3_public_access",
                    "params": {"bucket_name": bucket},
                    "confidence": 1.0,
                    "rationale": "Phase 19 lab bucket has public controls disabled",
                }
            ],
        }
        safety = invoke_json(
            lambdas,
            "cloudsec-lab-safety-validation",
            {
                "detail": {
                    "incident_id": incident_id,
                    "incident": incident,
                    "findings": [
                        {
                            "finding_id": incident["finding_id"],
                            "source": "lab_simulation",
                            "state_verified": True,
                        }
                    ],
                    "blast_radius": report["blast_radius"],
                    "report": report,
                }
            },
        )
        decision = safety["decisions"][0]
        decision_id = decision["decision_id"]
        if decision["level"] not in {1, 2}:
            raise AssertionError(f"Expected executable decision, got {decision}")
        execution_arn = wait_execution_for_decision(
            stepfunctions,
            config["state_machine_arn"],
            decision_id,
            datetime.fromisoformat(decision["created_at"]),
        )
        if decision["level"] == 2:
            if "night_time" not in decision.get("risk_factors", []):
                raise AssertionError(f"Unexpected Level 2 upgrade: {decision}")
            approvals = session.resource("dynamodb").Table(config["approval_decisions_table"])
            pending = wait_pending(approvals, decision_id)
            api_base = config["approval_api_url"].rstrip("/")
            code, _ = api_json(
                f"{api_base}/decisions/{decision_id}/approve",
                token,
                method="POST",
                body={},
            )
            if code != 200:
                raise AssertionError(f"Night-risk approval API returned {code}")
        result = wait_execution(stepfunctions, execution_arn)
        if result["status"] != "SUCCEEDED":
            raise AssertionError(
                f"Level 1 execution failed: {result.get('error')} {result.get('cause')}"
            )
        block = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
        if not all(block.values()):
            raise AssertionError(f"S3 public access was not fully blocked: {block}")
        stored = wait_incident(incidents, incident_id, event_time, {"RESOLVED", "ESCALATED"})
        if stored["status"] != "RESOLVED":
            raise AssertionError(f"Level 1 incident did not resolve: {stored}")
        prefix = f"evidence/{incident_id}/"
        required = {
            "investigation_report.json",
            "blast_radius_report.json",
            "verification_results.json",
            "remediation_history.json",
            "manifest.json",
            "incident_report.json",
            "incident_report.md",
        }
        deadline = time.monotonic() + 120
        present = set()
        while time.monotonic() < deadline:
            objects = s3.list_objects_v2(Bucket=config["evidence_bucket"], Prefix=prefix).get(
                "Contents", []
            )
            present = {item["Key"].rsplit("/", 1)[-1] for item in objects}
            if required <= present:
                break
            time.sleep(2)
        if not required <= present:
            raise AssertionError(f"Missing automatic evidence: {sorted(required - present)}")
        return {
            "scenario": "level1_auto_remediation",
            "incident_id": incident_id,
            "decision_level": decision["level"],
            "night_time_upgrade": decision["level"] == 2,
            "execution_status": result["status"],
            "execution_arn": execution_arn,
            "public_access_blocked": True,
            "incident_status": stored["status"],
            "preserved_files": len(present),
        }
    finally:
        if execution_arn:
            try:
                execution = stepfunctions.describe_execution(executionArn=execution_arn)
                if execution["status"] == "RUNNING":
                    stepfunctions.stop_execution(
                        executionArn=execution_arn,
                        error="Phase19Cleanup",
                        cause="Bounded live test cleanup",
                    )
            except Exception as exc:
                print(json.dumps({"cleanup_warning": str(exc), "execution": execution_arn}))
        if pending:
            session.resource("dynamodb").Table(config["approval_decisions_table"]).delete_item(
                Key={"decision_id": decision_id, "created_at": pending["created_at"]}
            )
        if decision_id:
            session.resource("dynamodb").Table(config["decisions_table"]).delete_item(
                Key={"decision_id": decision_id}
            )
        incidents.delete_item(Key={"incident_id": incident_id, "event_time": event_time})
        try:
            s3.delete_bucket(Bucket=bucket)
        except Exception as exc:
            print(json.dumps({"cleanup_warning": str(exc), "bucket": bucket}))


def level2_checkpoint(session, config, run_id, token, *, approve):
    iam = session.client("iam")
    lambdas = session.client("lambda")
    stepfunctions = session.client("stepfunctions")
    suffix = "approve" if approve else "reject"
    user = f"cloudsec-lab-e2e-{suffix}-{run_id}"
    incident_id = f"e2e-iam-{suffix}-{run_id}"
    event_time = datetime.now(UTC).isoformat()
    incidents = session.resource("dynamodb").Table(config["incidents_table"])
    approvals = session.resource("dynamodb").Table(config["approval_decisions_table"])
    key_id = None
    decision_id = None
    pending = None
    execution_arn = None
    try:
        iam.create_user(
            UserName=user,
            Path="/cloudsec-lab/e2e/",
            Tags=[
                {"Key": "Environment", "Value": "lab"},
                {"Key": "ManagedBy", "Value": "phase19-e2e"},
                {"Key": "E2ERunId", "Value": run_id},
            ],
        )
        key = iam.create_access_key(UserName=user)["AccessKey"]
        key_id = key["AccessKeyId"]
        incident = {
            "incident_id": incident_id,
            "event_time": event_time,
            "finding_id": f"e2e-finding-iam-{suffix}-{run_id}",
            "severity": "P2",
            "status": "REMEDIATING",
            "created_at": event_time,
        }
        incidents.put_item(Item=incident)
        report = {
            "incident_id": incident_id,
            "finding_type": "UnauthorizedAccess",
            "validation_status": "APPROVED",
            "cloudtrail_used": True,
            "last_used": event_time,
            "affected_principals": [{"arn": f"arn:aws:iam::{LAB_ACCOUNT}:user/{user}"}],
            "affected_resources": [],
            "evidence_citations": [{"evidence_id": "e2e", "quote": key_id}],
            "blast_radius": {"risk_score": 2},
            "recommended_actions": [
                {
                    "action": "disable_iam_key",
                    "params": {"user_name": user, "access_key_id": key_id},
                    "confidence": 1.0,
                    "rationale": "Phase 19 isolated lab approval checkpoint",
                }
            ],
        }
        safety = invoke_json(
            lambdas,
            "cloudsec-lab-safety-validation",
            {
                "detail": {
                    "incident_id": incident_id,
                    "incident": incident,
                    "findings": [
                        {
                            "finding_id": incident["finding_id"],
                            "source": "lab_simulation",
                            "state_verified": True,
                        }
                    ],
                    "blast_radius": report["blast_radius"],
                    "report": report,
                }
            },
        )
        decision = safety["decisions"][0]
        decision_id = decision["decision_id"]
        if decision["level"] != 2:
            raise AssertionError(f"Expected Level 2, got {decision}")
        execution_arn = wait_execution_for_decision(
            stepfunctions,
            config["state_machine_arn"],
            decision_id,
            datetime.fromisoformat(decision["created_at"]),
        )
        pending = wait_pending(approvals, decision_id)
        time.sleep(5)
        status = next(
            item["Status"]
            for item in iam.list_access_keys(UserName=user)["AccessKeyMetadata"]
            if item["AccessKeyId"] == key_id
        )
        if status != "Active":
            raise AssertionError("Level 2 key changed before human approval")
        api_base = config["approval_api_url"].rstrip("/")
        code, body = api_json(f"{api_base}/decisions/pending", token)
        if code != 200 or decision_id not in {item["decision_id"] for item in body["Items"]}:
            raise AssertionError("Pending decision was not visible through the approval API")
        route = "approve" if approve else "reject"
        code, _ = api_json(
            f"{api_base}/decisions/{decision_id}/{route}",
            token,
            method="POST",
            body={} if approve else {"reason": "Phase 19 rejection-path checkpoint"},
        )
        if code != 200:
            raise AssertionError(f"Approval API returned {code}")
        execution = wait_execution(stepfunctions, execution_arn)
        expected_execution = "SUCCEEDED" if approve else "FAILED"
        if execution["status"] != expected_execution:
            raise AssertionError(f"Expected {expected_execution}, got {execution}")
        key_status = next(
            item["Status"]
            for item in iam.list_access_keys(UserName=user)["AccessKeyMetadata"]
            if item["AccessKeyId"] == key_id
        )
        expected_key = "Inactive" if approve else "Active"
        if key_status != expected_key:
            raise AssertionError(f"Expected key {expected_key}, got {key_status}")
        expected_incident = "RESOLVED" if approve else "ESCALATED"
        stored = wait_incident(
            incidents, incident_id, event_time, {"RESOLVED", "ESCALATED"}
        )
        if stored["status"] != expected_incident:
            raise AssertionError(f"Expected incident {expected_incident}, got {stored}")
        return {
            "scenario": f"level2_{route}",
            "incident_id": incident_id,
            "decision_level": decision["level"],
            "key_status_while_waiting": status,
            "key_status_after_decision": key_status,
            "execution_status": execution["status"],
            "incident_status": stored["status"],
            "approval_api_verified": True,
        }
    finally:
        if execution_arn:
            try:
                execution = stepfunctions.describe_execution(executionArn=execution_arn)
                if execution["status"] == "RUNNING":
                    stepfunctions.stop_execution(
                        executionArn=execution_arn,
                        error="Phase19Cleanup",
                        cause="Bounded live test cleanup",
                    )
            except Exception as exc:
                print(json.dumps({"cleanup_warning": str(exc), "execution": execution_arn}))
        if pending:
            approvals.delete_item(
                Key={"decision_id": decision_id, "created_at": pending["created_at"]}
            )
        if decision_id:
            session.resource("dynamodb").Table(config["decisions_table"]).delete_item(
                Key={"decision_id": decision_id}
            )
        incidents.delete_item(Key={"incident_id": incident_id, "event_time": event_time})
        if key_id:
            iam.delete_access_key(UserName=user, AccessKeyId=key_id)
        try:
            iam.delete_user(UserName=user)
        except iam.exceptions.NoSuchEntityException:
            pass


def level3_rejection_checkpoint(session, config, run_id):
    lambdas = session.client("lambda")
    incidents = session.resource("dynamodb").Table(config["incidents_table"])
    cases = [
        (
            "unknown_action",
            {
                "action": "delete_all_buckets",
                "params": {},
                "confidence": 1.0,
                "rationale": "Deliberately unsupported Phase 19 action",
            },
            {"finding_type": "PublicS3Bucket"},
        ),
        (
            "evidence_mismatch",
            {
                "action": "block_s3_public_access",
                "params": {"bucket_name": "cloudsec-lab-not-in-evidence"},
                "confidence": 1.0,
                "rationale": "Deliberate evidence mismatch",
            },
            {
                "finding_type": "PublicS3Bucket",
                "affected_resources": [],
                "evidence_citations": [],
            },
        ),
        (
            "policy_false",
            {
                "action": "block_s3_public_access",
                "params": {"bucket_name": "cloudsec-lab-e2e-policy-check"},
                "confidence": 1.0,
                "rationale": "Deliberate policy mismatch",
            },
            {
                "finding_type": "CompromisedEC2",
                "affected_resources": [{"arn": "cloudsec-lab-e2e-policy-check"}],
                "evidence_citations": [],
            },
        ),
    ]
    rejected = []
    table = session.resource("dynamodb").Table(config["decisions_table"])
    for case_name, recommendation, fields in cases:
        incident_id = f"e2e-level3-{case_name}-{run_id}"
        event_time = datetime.now(UTC).isoformat()
        incident = {
            "incident_id": incident_id,
            "event_time": event_time,
            "finding_id": f"e2e-finding-level3-{case_name}-{run_id}",
            "severity": "P2",
            "status": "INVESTIGATING",
            "created_at": event_time,
        }
        incidents.put_item(Item=incident)
        report = {
            "incident_id": incident_id,
            "affected_principals": [],
            "affected_resources": [],
            "evidence_citations": [],
            "blast_radius": {"risk_score": 1},
            "recommended_actions": [recommendation],
            **fields,
        }
        response = invoke_json(
            lambdas,
            "cloudsec-lab-safety-validation",
            {"detail": {"incident_id": incident_id, "incident": incident, "report": report}},
        )
        decision = response["decisions"][0]
        try:
            if decision["level"] != 3 or decision["event_type"] != "RemediationRejected":
                raise AssertionError(f"Unsafe action was not rejected: {decision}")
            stored = wait_incident(incidents, incident_id, event_time, {"ESCALATED"})
            rejected.append(
                {
                    "case": case_name,
                    "reason": decision["reason"],
                    "incident_status": stored["status"],
                }
            )
        finally:
            table.delete_item(Key={"decision_id": decision["decision_id"]})
            incidents.delete_item(Key={"incident_id": incident_id, "event_time": event_time})
    return {
        "scenario": "level3_rejected_action",
        "rejected_cases": rejected,
        "state_changing_calls": 0,
    }


def evidence_and_reporting_checkpoint(session, config, run_id, execution_arn):
    now = datetime.now(UTC).isoformat()
    incident_id = f"e2e-evidence-{run_id}"
    incident = {
        "incident_id": incident_id,
        "event_time": now,
        "finding_id": f"e2e-finding-{run_id}",
        "severity": "P3",
        "status": "RESOLVED",
        "created_at": now,
        "resolved_at": now,
        "investigation_report": {
            "validation_status": "VALID",
            "root_cause": "Phase 19 isolated S3 exposure simulation",
            "recommended_actions": ["Keep S3 Block Public Access enabled"],
        },
        "blast_radius_report": {"risk_score": 1, "cross_account": False},
        "verification": {
            "status": "RESOLVED",
            "conditions": {
                "state_verified": True,
                "containment_confirmed": True,
                "no_new_findings": True,
            },
        },
        "actions_taken": [
            {"timestamp": now, "action": "block_s3_public_access", "status": "SUCCEEDED"}
        ],
    }
    incidents = session.resource("dynamodb").Table(config["incidents_table"])
    incidents.put_item(Item=incident)
    lambdas = session.client("lambda")
    detail = {
        "incident": incident,
        "investigation_report": incident["investigation_report"],
        "blast_radius_report": incident["blast_radius_report"],
        "verification_results": incident["verification"],
        "execution_arns": [execution_arn],
    }
    try:
        evidence = invoke_json(
            lambdas,
            "cloudsec-lab-evidence-packager",
            {"detail": detail},
        )
        report = invoke_json(
            lambdas,
            "cloudsec-lab-incident-reporting",
            {"detail": {"incident": incident, "verification": incident["verification"]}},
        )
        objects = (
            session.client("s3")
            .list_objects_v2(Bucket=config["evidence_bucket"], Prefix=f"evidence/{incident_id}/")
            .get("Contents", [])
        )
        keys = sorted(item["Key"] for item in objects)
        required = {
            "investigation_report.json",
            "blast_radius_report.json",
            "verification_results.json",
            "remediation_history.json",
            "manifest.json",
            "incident_report.json",
            "incident_report.md",
        }
        present = {key.rsplit("/", 1)[-1] for key in keys}
        if not required <= present:
            raise AssertionError(f"Missing preserved evidence: {sorted(required - present)}")
        return {
            "scenario": "evidence_and_reporting",
            "incident_id": incident_id,
            "evidence_manifest": evidence["manifest"]["overall_sha256"],
            "report_keys": report["report_keys"],
            "preserved_files": len(keys),
        }
    finally:
        incidents.delete_item(Key={"incident_id": incident_id, "event_time": now})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm-live-lab", action="store_true")
    args = parser.parse_args()
    if not args.confirm_live_lab:
        raise SystemExit("Refusing live changes without --confirm-live-lab")
    session = boto3.Session(region_name="us-east-1")
    account = session.client("sts").get_caller_identity()["Account"]
    if account != LAB_ACCOUNT:
        raise RuntimeError(f"Account mismatch: {account}")
    config = load_config(session)
    run_id = uuid.uuid4().hex[:12]
    approver = None
    try:
        approver, token = create_test_approver(session, config, run_id)
        results = [
            public_s3_checkpoint(session, config, run_id, token),
            level2_checkpoint(session, config, run_id, token, approve=True),
            level2_checkpoint(session, config, run_id, token, approve=False),
            level3_rejection_checkpoint(session, config, run_id),
        ]
        print(json.dumps({"account": account, "run_id": run_id, "results": results}, indent=2))
    finally:
        if approver:
            session.client("cognito-idp").admin_delete_user(
                UserPoolId=config["approval_user_pool_id"], Username=approver
            )


if __name__ == "__main__":
    main()
