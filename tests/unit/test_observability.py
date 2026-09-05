import json
import sys
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "lambda"))
from common.bedrock_metrics import emit_bedrock_metric  # noqa: E402
from common.logger import StructuredLogger  # noqa: E402
from common.operational_metrics import emit_metric  # noqa: E402


def test_structured_logger_outputs_required_redacted_json(monkeypatch):
    monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", "cloudsec-dev-test")
    sink = Mock()
    logger = StructuredLogger("test", sink=sink)
    logger.info(
        "processed",
        request_id="request-1",
        incident_id="incident-1",
        source="10.1.2.3",
    )
    payload = json.loads(sink.info.call_args.args[0])
    assert set(
        ["timestamp", "level", "function_name", "request_id", "incident_id", "message"]
    ).issubset(payload)
    assert payload["source"] == "[REDACTED_IP]"
    assert datetime.fromisoformat(payload["timestamp"]).tzinfo is not None
    assert "REDACTED" not in payload["timestamp"]


def test_structured_error_contains_diagnostics_without_secret():
    sink = Mock()
    error = ValueError("password=secret")
    StructuredLogger("test", sink=sink).error("failed", error=error)
    payload = json.loads(sink.error.call_args.args[0])
    assert payload["error_type"] == "ValueError"
    assert "[REDACTED_SECRET]" in payload["error_message"]
    assert payload["stack_trace"]


def test_custom_metric_emission():
    client = Mock()
    emit_metric("VerificationFailed", dimensions={"failure_type": "state"}, client=client)
    assert client.put_metric_data.call_args.kwargs["Namespace"] == "CloudSec/Operations"
    emit_bedrock_metric(
        "SchemaValidationError",
        dimension_name="validation_stage",
        dimension_value="report",
        client=client,
    )
    assert client.put_metric_data.call_args.kwargs["Namespace"] == "CloudSec/AI"
