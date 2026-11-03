"""End-to-end CLI tests: real Batfish, real verdicts, real exit codes.

Each scenario runs ``python -m netops_lens assess`` in a subprocess and
asserts the process contract: exit code, verdict text, and JSON shape.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

SCENARIOS = {
    "healthy": ("NO_REGRESSION_DETECTED", 0),
    "removed_route": ("REGRESSION_DETECTED", 0),
    "acl_blocks_db": ("REGRESSION_DETECTED", 0),
}


def _run(*argv: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "netops_lens", *argv],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=280,
    )


@pytest.mark.parametrize("scenario", list(SCENARIOS))
def test_cli_scenario_verdict_and_exit_code(batfish_session, scenario):
    del batfish_session  # health gate: skip with reason when Batfish is down
    # --no-investigate keeps this deterministic (no Meta API calls).
    proc = _run("assess", "--scenario", scenario, "--no-investigate")
    expected_verdict, expected_code = SCENARIOS[scenario]
    assert proc.returncode == expected_code, proc.stderr
    assert f"Verdict: {expected_verdict}" in proc.stdout


def test_cli_json_report_shape(batfish_session):
    del batfish_session
    proc = _run("assess", "--scenario", "removed_route", "--json", "--no-investigate")
    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout)
    assessment = report["assessment"]
    assert assessment["verdict"] == "REGRESSION_DETECTED"
    assert [c["flow_id"] for c in assessment["flow_comparisons"]] == ["app-to-db-icmp"]
    assert assessment["findings"], "regression must produce findings"
    for finding in assessment["findings"]:
        assert finding["evidence_ids"]
    assert report["investigation"] is None
    assert report["verifications"] == []
    assert set(report["evidence_index"]), "evidence index must be populated"


def test_cli_no_investigate_skips_stage_b(batfish_session):
    del batfish_session
    report = json.loads(
        _run("assess", "--scenario", "healthy", "--json", "--no-investigate").stdout
    )
    assert report["assessment"]["verdict"] == "NO_REGRESSION_DETECTED"
    assert report["investigation"] is None
    assert report["verifications"] == []


def test_cli_usage_errors_exit_1():
    proc = _run("assess", "--scenario", "no-such-scenario")
    assert proc.returncode == 1
    proc = _run("assess", "--baseline", "lab/baseline")
    assert proc.returncode == 1
    proc = _run("assess")
    assert proc.returncode == 1
    proc = _run(
        "assess",
        "--baseline",
        "lab/baseline",
        "--proposed",
        "lab/proposed",
        "--intent",
        "examples/missing.yaml",
    )
    assert proc.returncode == 1
