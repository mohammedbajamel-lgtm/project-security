"""Repository-wide pytest command-line controls."""

from __future__ import annotations

def pytest_addoption(parser):
    group = parser.getgroup("cloudsec-e2e")
    group.addoption("--run-e2e", action="store_true", help="enable isolated lab E2E tests")
    group.addoption(
        "--dry-run", action="store_true", help="validate E2E configuration without mutations"
    )
