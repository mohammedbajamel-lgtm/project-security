from datetime import UTC, datetime, timedelta

from botocore.exceptions import ClientError


class IdempotencyConflict(RuntimeError):  # noqa: N818 - name required by specification
    pass


def make_key(incident_id, action, principal_arn):
    return f"{incident_id}:{action}:{principal_arn}"


def acquire_lock(table, key, action, execution_id, *, now=None):
    current = now or datetime.now(UTC)
    item = {
        "idempotency_key": key,
        "action": action,
        "execution_id": execution_id,
        "expires_at": int((current + timedelta(minutes=30)).timestamp()),
    }
    try:
        table.put_item(
            Item=item,
            ConditionExpression=(
                "attribute_not_exists(idempotency_key) AND attribute_not_exists(#action)"
            ),
            ExpressionAttributeNames={"#action": "action"},
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            raise IdempotencyConflict(key) from exc
        raise
    return item


def release_lock(table, key, action):
    table.delete_item(Key={"idempotency_key": key, "action": action})
