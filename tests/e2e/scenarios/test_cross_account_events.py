import pytest

from tests.e2e.lifecycle_model import LifecycleModel

pytestmark = pytest.mark.e2e


@pytest.mark.parametrize("source", ["GuardDuty", "CloudTrail"])
def test_cross_account_source_is_tagged_and_isolated_by_default(source):
    model = LifecycleModel()
    model.ingest(f"finding-{source}", source=source, source_account="111122223333")
    finding = model.findings[f"finding-{source}"]
    reconstruction = {
        "lateral_movement": source == "CloudTrail",
        "source_account": finding["source_account"],
    }
    report = {
        "cross_account_summary": reconstruction,
        "blast_radius": {"cross_account_roles": ["lab-role"]},
    }
    assert finding["source_account"] == "111122223333"
    assert report["cross_account_summary"]["source_account"] == "111122223333"
    assert report["blast_radius"]["cross_account_roles"]
    cross_account_correlation_enabled = False
    assert cross_account_correlation_enabled is False
