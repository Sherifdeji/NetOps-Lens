"""Live Stage B tests: real Batfish + real Meta Model API.

Skipped with a reason when META_API_KEY is absent or Batfish is down.
These exercise candidate collection only: nothing is applied or verified.
"""

from __future__ import annotations

import json
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

from netops_lens.assessment import run_mandatory_assessment
from netops_lens.batfish_client import BatfishClient
from netops_lens.cli import load_manifest
from netops_lens.config import load_settings
from netops_lens.evidence import EvidenceStore
from netops_lens.intent import load_intent
from netops_lens.agent import run_stage_b

REPO_ROOT = Path(__file__).resolve().parent.parent


def _settings():
    settings = load_settings()
    if settings.meta_api_key is None:
        pytest.skip("META_API_KEY not configured; live Stage B test skipped")
    return settings


def _scenario_paths(scenario: str):
    manifest = load_manifest(REPO_ROOT / "lab" / "scenarios" / "manifest.yaml")
    entry = manifest["scenarios"][scenario]
    return (
        REPO_ROOT / entry["baseline_path"],
        REPO_ROOT / entry["proposed_path"],
        REPO_ROOT / entry["intent_path"],
    )


def _live_run(batfish_session, scenario: str, question: str = ""):
    """Full Stage A + live Stage B in a unique run-scoped network."""
    del batfish_session  # health gate: skip with reason when Batfish is down
    settings = _settings()
    baseline_dir, proposed_dir, intent_path = _scenario_paths(scenario)
    intent = load_intent(intent_path)
    network = f"netops-lens-live-{scenario}-{uuid.uuid4().hex[:8]}"
    client = BatfishClient(settings.batfish_host, network)
    from netops_lens.models import SnapshotRef

    baseline_ref = SnapshotRef(name="live-baseline", path=str(baseline_dir))
    proposed_ref = SnapshotRef(name="live-proposed", path=str(proposed_dir))
    store = EvidenceStore()
    try:
        client.connect()
        client.init_snapshot(baseline_dir, baseline_ref.name)
        client.init_snapshot(proposed_dir, proposed_ref.name)
        before = run_mandatory_assessment(client, store, baseline_ref, proposed_ref, intent)
        before_hash = before.model_dump_json()
        investigation = run_stage_b(
            client,
            store,
            before,
            intent,
            baseline_ref,
            proposed_ref,
            question=question,
            settings=settings,
        )
    finally:
        try:
            client.delete_network()
        except Exception:
            pass
    assert before.model_dump_json() == before_hash
    return before, investigation


def _tool_names(investigation) -> list[str]:
    return [entry.tool for entry in investigation.tool_activity]


def test_live_removed_route_investigation(batfish_session):
    assessment, investigation = _live_run(batfish_session, "removed_route")
    assert assessment.verdict == "REGRESSION_DETECTED"
    tools = _tool_names(investigation)
    assert "trace_flow" in tools
    assert "get_routes" in tools
    assert investigation.candidates, "model submitted no candidate"
    ops = [op for c in investigation.candidates for op in c.operations]
    assert any(
        op.op == "add_static_route"
        and op.node == "r1"
        and op.prefix == "198.51.100.0/24"
        and op.next_hop == "10.0.12.2"
        for op in ops
    ), f"no evidenced add_static_route op: {_diag(investigation)}"


def _diag(investigation) -> str:
    ops = [
        (c.candidate_id, [(op.op, op.model_dump()) for op in c.operations])
        for c in investigation.candidates
    ]
    return (
        f"narrative={investigation.narrative!r} "
        f"tools={_tool_names(investigation)} candidates={ops}"
    )


def test_live_acl_investigation(batfish_session):
    assessment, investigation = _live_run(batfish_session, "acl_blocks_db")
    assert assessment.verdict == "REGRESSION_DETECTED"
    tools = _tool_names(investigation)
    assert "trace_flow" in tools
    assert "get_acl_rules" in tools
    assert investigation.candidates, f"model submitted no candidate: {_diag(investigation)}"
    ops = [op for c in investigation.candidates for op in c.operations]
    removes = [op for op in ops if op.op == "remove_acl_line"]
    permits = [op for op in ops if op.op == "acl_permit"]
    assert any(
        op.node == "r1"
        and op.acl == "DB-FILTER"
        and op.sequence_number == 10
        and op.expected_rule.action.value == "deny"
        and op.expected_rule.dst_port == 1433
        for op in removes
    ), f"no evidenced seq-10 removal: {_diag(investigation)}"
    assert any(
        op.node == "r1" and op.acl == "DB-FILTER" and op.sequence_number == 10
        for op in permits
    ), f"no seq-10 permit: {_diag(investigation)}"


def test_live_healthy_explain_only(batfish_session):
    assessment, investigation = _live_run(batfish_session, "healthy")
    assert assessment.verdict == "NO_REGRESSION_DETECTED"
    assert investigation.candidates == []
    assert "submit_candidate_patch" not in _tool_names(investigation)
    assert investigation.narrative and investigation.narrative.strip()


def test_live_assessment_identical_with_and_without_investigation(batfish_session):
    del batfish_session  # health gate
    _settings()

    def run(*argv: str) -> dict:
        proc = subprocess.run(
            [sys.executable, "-m", "netops_lens", *argv],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=280,
        )
        assert proc.returncode == 0, proc.stderr
        return json.loads(proc.stdout)

    plain = run("assess", "--scenario", "healthy", "--json")
    flagged = run("assess", "--scenario", "healthy", "--json", "--no-investigate")
    assert plain["assessment"] == flagged["assessment"]
    assert plain["investigation"] is not None
    assert flagged["investigation"] is None
