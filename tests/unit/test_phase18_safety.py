import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SIMULATIONS = ROOT / "lab" / "simulations"


def test_all_six_simulations_have_mandatory_guard_and_cleanup():
    scripts = sorted(SIMULATIONS.glob("simulate_*.py"))
    assert len(scripts) == 6
    for script in scripts:
        source = script.read_text(encoding="utf-8")
        ast.parse(source)
        assert "guard(args)" in source
        assert "args.cleanup" in source
        assert "dry_run" in source


def test_shared_safety_boundary_is_account_and_prefix_locked():
    source = (SIMULATIONS / "common.py").read_text(encoding="utf-8")
    assert 'os.environ.get("CLOUDSEC_LAB_ACCOUNT_ID", "")' in source
    assert 'PREFIX = "cloudsec-lab-"' in source
    assert "Refusing to run without --lab" in source
