"""Pytest controls and guarded fixtures for Phase 19."""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

from tests.e2e.test_config import LAB_ACCOUNT_ID
from tests.e2e.test_harness import E2ETestRunner

LAMBDA_ROOT = Path(__file__).resolve().parents[2] / "lambda"
if str(LAMBDA_ROOT) not in sys.path:
    sys.path.insert(0, str(LAMBDA_ROOT))


def pytest_collection_modifyitems(config, items):
    if config.getoption("--run-e2e"):
        return
    skip = pytest.mark.skip(reason="requires explicit --run-e2e")
    for item in items:
        if "e2e" in item.keywords or "e2e_live" in item.keywords:
            item.add_marker(skip)


@pytest.fixture(scope="session")
def e2e_runner(request):
    runner = E2ETestRunner(dry_run=request.config.getoption("--dry-run"))
    yield runner
    runner.cleanup()


@pytest.fixture(scope="session")
def lab_account_id(e2e_runner):
    assert e2e_runner.expected_account_id == LAB_ACCOUNT_ID
    return LAB_ACCOUNT_ID


@pytest.fixture
def clean_findings(e2e_runner):
    # Never truncate a shared table; E2E items are uniquely prefixed and tracked.
    yield e2e_runner.config["findings_table"]
    e2e_runner.cleanup()


@pytest.fixture
def wait_for_event():
    def wait(probe, timeout=600, interval=0.05):
        deadline = time.monotonic() + min(timeout, 600)
        while time.monotonic() < deadline:
            result = probe()
            if result:
                return result
            time.sleep(interval)
        raise TimeoutError("Event was not observed within the E2E timeout")

    return wait
