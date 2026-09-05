"""Structured JSON logging with automatic secret redaction."""

import json
import logging
import os
import traceback
from datetime import UTC, datetime
from functools import wraps

from knowledge_base.redactor import redact_incident_data


class StructuredLogger:
    def __init__(self, name, *, sink=None):
        self.name = name
        self.sink = sink or logging.getLogger(name)

    def _emit(self, level, message, **fields):
        request_id = fields.pop("request_id", None)
        incident_id = fields.pop("incident_id", None)
        # Redact application-controlled content only. Operational metadata such
        # as the ISO-8601 timestamp must retain its exact machine-readable form.
        safe_content = redact_incident_data({"message": message, **fields})
        record = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": level,
            "function_name": os.getenv("AWS_LAMBDA_FUNCTION_NAME", self.name),
            "request_id": request_id,
            "incident_id": incident_id,
            **safe_content,
        }
        getattr(self.sink, level.lower())(json.dumps(record, default=str))
        return record

    def info(self, message, **fields):
        return self._emit("INFO", message, **fields)

    def warning(self, message, **fields):
        return self._emit("WARNING", message, **fields)

    def error(self, message, *, error=None, **fields):
        if error is not None:
            fields.update(
                error_type=type(error).__name__,
                error_message=str(error),
                stack_trace="".join(traceback.format_exception(error)),
            )
        return self._emit("ERROR", message, **fields)


def get_logger(name):
    return StructuredLogger(name)


def log_invocation(name):
    """Log Lambda start, completion, and uncaught failure without payload data."""

    logger = get_logger(name)

    def decorate(handler):
        @wraps(handler)
        def wrapped(event, context=None, *args, **kwargs):
            detail = event.get("detail", event) if isinstance(event, dict) else {}
            incident = detail.get("incident", detail) if isinstance(detail, dict) else {}
            incident_id = incident.get("incident_id") if isinstance(incident, dict) else None
            request_id = getattr(context, "aws_request_id", None)
            fields = {"request_id": request_id, "incident_id": incident_id}
            logger.info("invocation_started", **fields)
            try:
                result = handler(event, context, *args, **kwargs)
            except Exception as exc:
                logger.error("invocation_failed", error=exc, **fields)
                raise
            logger.info("invocation_completed", **fields)
            return result

        return wrapped

    return decorate
