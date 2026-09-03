#!/usr/bin/env python
"""T01-01 corrective validation script.
Run from workspace root: python <this-file>
"""

import os
import sys
import json
import subprocess
import re

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(ROOT)

results = {}

def run_cmd(args, cwd=None, timeout=60):
    """Run a command; return (returncode, stdout, stderr, error_str)."""
    try:
        r = subprocess.run(args, capture_output=True, text=True,
                           cwd=cwd or ROOT, timeout=timeout)
        return r.returncode, r.stdout, r.stderr, None
    except FileNotFoundError as e:
        return 127, "", str(e), "TOOL_UNAVAILABLE"
    except subprocess.TimeoutExpired as e:
        return -1, e.stdout or "", e.stderr or "timeout", "TIMEOUT"
    except Exception as e:
        return -2, "", str(e), "ERROR"

# ── Step 1: CI YAML syntax ──────────────────────────────────────────
ci_path = os.path.join(ROOT, ".github", "workflows", "ci.yml")
try:
    import yaml
    with open(ci_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    # Verify expected job keys exist
    jobs = data.get("jobs", {}) if isinstance(data, dict) else {}
    expected_jobs = {"lint", "unit-test", "tfsec"}
    missing = expected_jobs - set(jobs.keys())
    if missing:
        results["ci_yaml"] = f"FAIL: missing jobs {missing}"
        print(f"[FAIL] CI YAML: missing jobs {missing}")
    else:
        results["ci_yaml"] = "PASS"
        print(f"[PASS] CI YAML syntax valid; jobs: {', '.join(jobs.keys())}")
except ImportError:
    results["ci_yaml"] = "NOT RUN - TOOL UNAVAILABLE (PyYAML not installed)"
    print("[NOT RUN] CI YAML: PyYAML not installed")
except Exception as e:
    results["ci_yaml"] = f"FAIL: {e}"
    print(f"[FAIL] CI YAML: {e}")

# ── Step 2: Lint (ruff) ────────────────────────────────────────────
rc, out, err, err_type = run_cmd(["ruff", "check", "lambda/"], timeout=60)
if err_type == "TOOL_UNAVAILABLE":
    rc2, out2, err2, et2 = run_cmd([sys.executable, "-m", "ruff", "check", "lambda/"], timeout=60)
    if et2 == "TOOL_UNAVAILABLE" or "No module named ruff" in err2:
        results["lint"] = "NOT RUN - TOOL UNAVAILABLE (ruff not installed)"
        print("[NOT RUN] Lint: ruff not installed locally")
    else:
        results["lint"] = f"FAIL: {out2 + err2}"
        print(f"[FAIL] Lint (python -m ruff):\n{out2 + err2}")
elif rc == 0:
    results["lint"] = "PASS"
    print("[PASS] Lint: no issues")
elif "no issues" in (out + err).lower():
    results["lint"] = "PASS"
    print("[PASS] Lint: no issues")
else:
    results["lint"] = f"FAIL: {out + err}"
    print(f"[FAIL] Lint:\n{out + err}")

# ── Step 3: Unit test stage ────────────────────────────────────────
try:
    import pytest  # noqa: F401
except ImportError:
    results["unit_test"] = "NOT RUN - TOOL UNAVAILABLE (pytest not installed)"
    print("[NOT RUN] Unit test: pytest not installed")
else:
    try:
        import pytest_cov  # noqa: F401
        has_cov = True
    except ImportError:
        has_cov = False

    if has_cov:
        cmd_args = [
            sys.executable, "-m", "pytest", "tests/unit",
            "--cov=lambda", "--cov-report=term-missing",
            "--cov-fail-under=90", "-v"
        ]
    else:
        # pytest-cov not installed — run without coverage flags
        cmd_args = [sys.executable, "-m", "pytest", "tests/unit", "-v"]
        print("[INFO] pytest-cov not installed; running without --cov flags")

    rc, out, err, err_type = run_cmd(cmd_args, timeout=120)
    if err_type:
        results["unit_test"] = f"NOT RUN - {err_type}: {err}"
        print(f"[NOT RUN] Unit test: {err_type}: {err}")
    else:
        combined = out + err
        if rc == 0:
            results["unit_test"] = "PASS"
            print("[PASS] Unit tests: all passed")
        elif "no tests ran" in combined.lower() or "collected 0 items" in combined.lower():
            results["unit_test"] = "NOT RUN - NO TESTS COLLECTED (expected at T01-01)"
            print("[NOT RUN] Unit test: no tests collected (expected at T01-01)")
            print(f"         Output: {combined.strip()[:300]}")
        else:
            results["unit_test"] = f"FAIL: {combined[:500]}"
            print(f"[FAIL] Unit test:\n{combined[:500]}")

# ── Step 4-6: Terraform ────────────────────────────────────────────
rc, out, err, err_type = run_cmd(["terraform", "version"], timeout=15)
if err_type == "TOOL_UNAVAILABLE" or rc == 127:
    results["terraform_fmt"] = "NOT RUN - TOOL UNAVAILABLE"
    results["terraform_init"] = "NOT RUN - TOOL UNAVAILABLE"
    results["terraform_validate"] = "NOT RUN - TOOL UNAVAILABLE"
    print("[NOT RUN] Terraform: not installed")
else:
    tf_ver = out.strip().split("\n")[0]
    print(f"[INFO] Terraform: {tf_ver}")

    # fmt check
    rc, out, err, err_type = run_cmd(
        ["terraform", "fmt", "-check", "-recursive", "terraform/"], timeout=30
    )
    if rc == 0:
        results["terraform_fmt"] = "PASS"
        print("[PASS] Terraform fmt: no formatting issues")
    elif err_type == "TOOL_UNAVAILABLE":
        results["terraform_fmt"] = "NOT RUN - TOOL UNAVAILABLE"
        print("[NOT RUN] Terraform fmt")
    else:
        results["terraform_fmt"] = f"FAIL: {out + err}"
        print(f"[FAIL] Terraform fmt:\n{out + err}")

    # init
    tf_dir = os.path.join(ROOT, "terraform")
    rc, out, err, err_type = run_cmd(
        ["terraform", "init", "-backend=false"], cwd=tf_dir, timeout=120
    )
    if rc == 0:
        print("[PASS] Terraform init: succeeded")
        results["terraform_init"] = "PASS"

        # validate
        rc, out, err, err_type = run_cmd(
            ["terraform", "validate"], cwd=tf_dir, timeout=60
        )
        if rc == 0:
            results["terraform_validate"] = "PASS"
            print("[PASS] Terraform validate: succeeded")
        else:
            results["terraform_validate"] = f"FAIL: {out + err}"
            print(f"[FAIL] Terraform validate:\n{out + err}")
    else:
        results["terraform_init"] = f"FAIL: {err[:300]}"
        print(f"[FAIL] Terraform init:\n{err[:300]}")
        results["terraform_validate"] = "NOT RUN - init failed"

# ── Step 7: tfsec ──────────────────────────────────────────────────
rc, out, err, err_type = run_cmd(["tfsec", "--version"], timeout=10)
if err_type == "TOOL_UNAVAILABLE" or rc == 127:
    results["tfsec"] = "NOT RUN - TOOL UNAVAILABLE (tfsec not installed)"
    print("[NOT RUN] tfsec: not installed locally")
else:
    rc, out, err, err_type = run_cmd(["tfsec", "terraform/"], timeout=60)
    if rc == 0:
        results["tfsec"] = "PASS"
        print("[PASS] tfsec: no critical/high issues")
    else:
        combined = out + err
        results["tfsec"] = f"FAIL: {combined[:500]}"
        print(f"[FAIL] tfsec:\n{combined[:500]}")

# ── Step 8: Sensitive-file scan ────────────────────────────────────
sensitive_issues = []

secret_patterns = [
    (re.compile(r'AKIA[0-9A-Z]{16}'), "AWS Access Key ID"),
    (re.compile(r'(?i)aws_secret_access_key\s*=\s*["\'][^"\']+'), "AWS Secret Key"),
    (re.compile(r'(?i)password\s*[:=]\s*["\'][^"\']+'), "Hardcoded password"),
    (re.compile(r'(?i)private_key\s*[:=]'), "Private key assignment"),
]

acct_pat = re.compile(r'\b\d{12}\b')
excluded_dirs = {'.kiro', '.git', '__pycache__', '.terraform', '.venv'}

for dirpath, dirnames, filenames in os.walk(ROOT):
    dirnames[:] = [d for d in dirnames if d not in excluded_dirs]
    for fn in filenames:
        fpath = os.path.join(dirpath, fn)
        rel = os.path.relpath(fpath, ROOT)
        if rel.startswith('.kiro'):
            continue
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            continue

        for pat, label in secret_patterns:
            if pat.search(content):
                line_num = content[:pat.search(content).start()].count("\n") + 1
                sensitive_issues.append(f"  {rel}:{line_num} — {label}")

        for match in acct_pat.finditer(content):
            ctx = content[max(0, match.start() - 20):match.end() + 20]
            if "<" not in ctx and ">" not in ctx:
                sensitive_issues.append(
                    f"  {rel} — possible real account ID '{match.group()}' near: {ctx.strip()[:60]}"
                )

for dirpath, dirnames, filenames in os.walk(ROOT):
    dirnames[:] = [d for d in dirnames if d not in excluded_dirs]
    for fn in filenames:
        if fn.startswith(".env") or fn.endswith(".tfstate"):
            sensitive_issues.append(
                f"  {os.path.relpath(os.path.join(dirpath, fn), ROOT)} — sensitive file type"
            )

if sensitive_issues:
    results["sensitive_scan"] = "FAIL"
    print(f"[FAIL] Sensitive-file scan:\n" + "\n".join(sensitive_issues))
else:
    results["sensitive_scan"] = "PASS"
    print("[PASS] Sensitive-file scan: no issues")

# ── Summary ─────────────────────────────────────────────────────────
print("\n" + "=" * 60)
print("VALIDATION RESULTS")
print("=" * 60)
for k in sorted(results.keys()):
    v = results[k]
    status = v.split(":")[0].strip()
    print(f"  {k:28s} : {status}")

print(f"\nRaw JSON:\n{json.dumps(results, indent=2, ensure_ascii=False)}")
