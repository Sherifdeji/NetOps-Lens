"""Assessment engine tests: truth tables synthetic, orchestration faked.

No Batfish, no LLM. Live behavior is covered by test_tools_integration.py
and test_e2e.py; here ``FakeClient`` stands in for Batfish with canned
records shaped exactly like the observed answers.
"""

from __future__ import annotations

import pytest

from netops_lens.assessment import (
    classify_flow,
    decide_verdict,
    reconcile_flow,
    run_mandatory_assessment,
)
from netops_lens.evidence import EvidenceStore
from netops_lens.models import FlowKind, Intent, Reachability, SnapshotRef
from tests._fakes import FakeClient, differential_row, multi_differential_row, trace_row

BASE = SnapshotRef(name="base", path="lab/baseline")
PROP = SnapshotRef(name="prop", path="lab/proposed")


def _intent() -> Intent:
    return Intent(
        version=1,
        must_reach=[
            {
                "flow_id": "reach-icmp",
                "src_ip": "192.0.2.10",
                "dst_ip": "198.51.100.1",
                "protocol": "ICMP",
                "start_location": "@enter(r1[GigabitEthernet0/1])",
            }
        ],
        must_not_reach=[
            {
                "flow_id": "blocked-tcp",
                "src_ip": "192.0.2.10",
                "dst_ip": "198.51.100.1",
                "protocol": "TCP",
                "dst_port": 22,
                "start_location": "@enter(r1[GigabitEthernet0/1])",
            }
        ],
    )


GRID: list[tuple[FlowKind, Reachability, Reachability, str]] = [
    ("must_reach", "REACHABLE", "REACHABLE", "NO_CHANGE_OK"),
    ("must_reach", "REACHABLE", "UNREACHABLE", "REGRESSION"),
    ("must_reach", "REACHABLE", "UNKNOWN", "UNKNOWN"),
    ("must_reach", "UNREACHABLE", "REACHABLE", "IMPROVEMENT"),
    ("must_reach", "UNREACHABLE", "UNREACHABLE", "PRE_EXISTING_VIOLATION"),
    ("must_reach", "UNREACHABLE", "UNKNOWN", "UNKNOWN"),
    ("must_reach", "UNKNOWN", "REACHABLE", "UNKNOWN"),
    ("must_reach", "UNKNOWN", "UNREACHABLE", "UNKNOWN"),
    ("must_reach", "UNKNOWN", "UNKNOWN", "UNKNOWN"),
    ("must_not_reach", "UNREACHABLE", "UNREACHABLE", "NO_CHANGE_OK"),
    ("must_not_reach", "UNREACHABLE", "REACHABLE", "REGRESSION"),
    ("must_not_reach", "UNREACHABLE", "UNKNOWN", "UNKNOWN"),
    ("must_not_reach", "REACHABLE", "UNREACHABLE", "IMPROVEMENT"),
    ("must_not_reach", "REACHABLE", "REACHABLE", "PRE_EXISTING_VIOLATION"),
    ("must_not_reach", "REACHABLE", "UNKNOWN", "UNKNOWN"),
    ("must_not_reach", "UNKNOWN", "UNREACHABLE", "UNKNOWN"),
    ("must_not_reach", "UNKNOWN", "REACHABLE", "UNKNOWN"),
    ("must_not_reach", "UNKNOWN", "UNKNOWN", "UNKNOWN"),
]


@pytest.mark.parametrize("kind,base,prop,expected", GRID)
def test_per_flow_grid(kind, base, prop, expected):
    assert classify_flow(kind, base, prop) == expected


@pytest.mark.parametrize(
    "health_ok,classifications,expected",
    [
        (True, ["NO_CHANGE_OK", "NO_CHANGE_OK"], "NO_REGRESSION_DETECTED"),
        (True, ["REGRESSION"], "REGRESSION_DETECTED"),
        (True, ["REGRESSION"], "REGRESSION_DETECTED"),
        (True, ["REGRESSION", "UNKNOWN"], "REGRESSION_DETECTED"),
        (True, ["UNKNOWN"], "INCONCLUSIVE"),
        (True, ["PRE_EXISTING_VIOLATION"], "INCONCLUSIVE"),
        (True, ["PRE_EXISTING_VIOLATION"], "INCONCLUSIVE"),
        (True, ["REGRESSION", "PRE_EXISTING_VIOLATION"], "REGRESSION_DETECTED"),
        (True, ["IMPROVEMENT"], "NO_REGRESSION_DETECTED"),
        (True, ["IMPROVEMENT", "NO_CHANGE_OK"], "NO_REGRESSION_DETECTED"),
        (False, ["REGRESSION"], "INCONCLUSIVE"),
        (False, ["NO_CHANGE_OK"], "INCONCLUSIVE"),
        (True, ["UNKNOWN", "NO_CHANGE_OK"], "INCONCLUSIVE"),
        (True, ["PRE_EXISTING_VIOLATION", "UNKNOWN"], "INCONCLUSIVE"),
    ],
)
def test_verdict_precedence(health_ok, classifications, expected):
    assert decide_verdict(health_ok, classifications) == expected


def test_reconcile_direct_change_without_corroboration():
    classification, note = reconcile_flow(
        "must_reach",
        "REACHABLE",
        "UNREACHABLE",
        reported_changed=False,
        consistent=True,
        diff_ok=True,
    )
    assert classification == "UNKNOWN"
    assert note == "direct checks indicate change, differential does not corroborate"


def test_reconcile_direct_change_with_conflicting_differential():
    classification, note = reconcile_flow(
        "must_reach",
        "REACHABLE",
        "UNREACHABLE",
        reported_changed=True,
        consistent=False,
        diff_ok=True,
    )
    assert classification == "UNKNOWN"
    assert "does not corroborate" in (note or "")


def test_reconcile_direct_conflict_without_direct_change():
    classification, note = reconcile_flow(
        "must_reach",
        "REACHABLE",
        "REACHABLE",
        reported_changed=True,
        consistent=False,
        diff_ok=True,
    )
    assert classification == "UNKNOWN"
    assert "conflicting" in (note or "")


def test_reconcile_empty_differential_keeps_direct_result():
    classification, note = reconcile_flow(
        "must_reach",
        "REACHABLE",
        "REACHABLE",
        reported_changed=False,
        consistent=True,
        diff_ok=True,
    )
    assert (classification, note) == ("NO_CHANGE_OK", None)


def test_reconcile_differential_error_forces_unknown():
    classification, note = reconcile_flow(
        "must_reach",
        "REACHABLE",
        "REACHABLE",
        reported_changed=None,
        consistent=False,
        diff_ok=False,
    )
    assert classification == "UNKNOWN"
    assert "cross-check incomplete" in (note or "")


def _fake_ok(
    base_disp: str = "ACCEPTED",
    prop_disp: str = "NO_ROUTE",
    diff_rows_base: str | None = "NO_ROUTE",
) -> FakeClient:
    answers = {
        ("traceroute", "base"): [trace_row(base_disp)],
        ("traceroute", "prop"): [trace_row(prop_disp)],
        ("differentialReachability", "prop"): (
            [differential_row("NO_ROUTE", "ACCEPTED")] if diff_rows_base else []
        ),
    }
    return FakeClient(answers=answers)


def test_mandatory_run_checks_every_flow_everywhere():
    client = _fake_ok()
    store = EvidenceStore()
    result = run_mandatory_assessment(client, store, BASE, PROP, _intent())
    assert client.asked("traceroute", "base") == 2
    assert client.asked("traceroute", "prop") == 2
    assert client.asked("differentialReachability", "prop") == 2
    assert [c.flow_id for c in result.flow_comparisons] == ["reach-icmp", "blocked-tcp"]
    assert result.verdict == "REGRESSION_DETECTED"
    assert len(store) == 2 + 2 + 2 + 2  # health x2, checks x4, differentials x2


def test_not_ok_health_gates_verdict():
    from netops_lens.batfish_client import HealthRecords

    failing = HealthRecords(
        parse_status=({"File_Name": "configs/r1.cfg", "Status": "FAILED"},),
        init_issues=(),
        nodes=({"Node": "r1"}, {"Node": "r2"}),
    )
    client = FakeClient(health=failing)
    client.answers = {
        ("traceroute", "base"): [trace_row("ACCEPTED")],
        ("traceroute", "prop"): [trace_row("NO_ROUTE")],
        ("differentialReachability", "prop"): [differential_row("NO_ROUTE", "ACCEPTED")],
    }
    store = EvidenceStore()
    result = run_mandatory_assessment(client, store, BASE, PROP, _intent())
    assert result.verdict == "INCONCLUSIVE"
    assert result.health[0].status == "NOT_OK"
    assert any("health NOT_OK" in reason for reason in result.inconclusive_reasons)


def test_tool_error_becomes_unknown_not_guessed():
    client = _fake_ok()
    client.failures = {("traceroute", "prop")}
    store = EvidenceStore()
    result = run_mandatory_assessment(client, store, BASE, PROP, _intent())
    by_id = {c.flow_id: c for c in result.flow_comparisons}
    assert by_id["reach-icmp"].proposed_reach == "UNKNOWN"
    assert by_id["reach-icmp"].classification == "UNKNOWN"
    assert result.verdict == "INCONCLUSIVE"
    assert any("reach-icmp" in reason for reason in result.inconclusive_reasons)


def test_direct_differential_contradiction_becomes_unknown():
    answers = {
        ("traceroute", "base"): [trace_row("ACCEPTED")],
        ("traceroute", "prop"): [trace_row("ACCEPTED")],
        ("differentialReachability", "prop"): [differential_row("NO_ROUTE", "ACCEPTED")],
    }
    client = FakeClient(answers=answers)
    store = EvidenceStore()
    result = run_mandatory_assessment(client, store, BASE, PROP, _intent())
    assert result.flow_comparisons[0].classification == "UNKNOWN"
    assert result.verdict == "INCONCLUSIVE"


def test_uncorroborated_change_records_discrepancy_finding():
    client = _fake_ok(diff_rows_base=None)
    store = EvidenceStore()
    result = run_mandatory_assessment(client, store, BASE, PROP, _intent())
    assert result.flow_comparisons[0].classification == "UNKNOWN"
    assert any(f.claim_type.value == "REACHABILITY_CHANGED" for f in result.findings)
    assert any("does not corroborate" in r for r in result.inconclusive_reasons)


def test_assessment_result_stays_deeply_immutable():
    client = _fake_ok()
    result = run_mandatory_assessment(client, EvidenceStore(), BASE, PROP, _intent())
    with pytest.raises(Exception):
        result.verdict = "NO_REGRESSION_DETECTED"  # type: ignore[misc]
    with pytest.raises(Exception):
        result.flow_comparisons[0].classification = "NO_CHANGE_OK"  # type: ignore[misc]


def test_reconcile_ambiguous_traces_forces_unknown():
    classification, note = reconcile_flow(
        "must_reach",
        "REACHABLE",
        "UNREACHABLE",
        reported_changed=True,
        consistent=False,
        diff_ok=False,
        ambiguous=True,
    )
    assert classification == "UNKNOWN"
    assert "ambiguous" in (note or "")


def test_reconcile_denied_family_agrees_with_unreachable_direct():
    """NO_ROUTE -> DENIED_IN is UNREACHABLE -> UNREACHABLE, not a regression."""
    classification, note = reconcile_flow(
        "must_not_reach",
        "UNREACHABLE",
        "UNREACHABLE",
        reported_changed=True,
        consistent=True,
        diff_ok=True,
    )
    assert (classification, note) == ("NO_CHANGE_OK", None)
    classification, note = reconcile_flow(
        "must_reach",
        "UNREACHABLE",
        "UNREACHABLE",
        reported_changed=True,
        consistent=True,
        diff_ok=True,
    )
    assert (classification, note) == ("PRE_EXISTING_VIOLATION", None)


def test_reconcile_accepted_to_noroute_needs_corroboration():
    classification, _ = reconcile_flow(
        "must_reach",
        "REACHABLE",
        "UNREACHABLE",
        reported_changed=True,
        consistent=True,
        diff_ok=True,
    )
    assert classification == "REGRESSION"
    classification, note = reconcile_flow(
        "must_reach",
        "REACHABLE",
        "UNREACHABLE",
        reported_changed=True,
        consistent=False,
        diff_ok=True,
    )
    assert classification == "UNKNOWN"
    assert note is not None


def test_run_denied_family_row_preserves_no_change():
    answers = {
        ("traceroute", "base"): [trace_row("NO_ROUTE")],
        ("traceroute", "prop"): [trace_row("DENIED_IN")],
        ("differentialReachability", "prop"): [multi_differential_row(["DENIED_IN"], ["NO_ROUTE"])],
    }
    client = FakeClient(answers=answers)
    store = EvidenceStore()
    result = run_mandatory_assessment(client, store, BASE, PROP, _intent())
    by_id = {c.flow_id: c for c in result.flow_comparisons}
    assert by_id["reach-icmp"].classification == "PRE_EXISTING_VIOLATION"
    assert by_id["blocked-tcp"].classification == "NO_CHANGE_OK"


def test_run_ambiguous_differential_forces_unknown():
    answers = {
        ("traceroute", "base"): [trace_row("ACCEPTED")],
        ("traceroute", "prop"): [trace_row("NO_ROUTE")],
        ("differentialReachability", "prop"): [
            multi_differential_row(["NO_ROUTE", "ACCEPTED"], ["ACCEPTED"])
        ],
    }
    client = FakeClient(answers=answers)
    store = EvidenceStore()
    result = run_mandatory_assessment(client, store, BASE, PROP, _intent())
    assert result.flow_comparisons[0].classification == "UNKNOWN"
    assert result.verdict == "INCONCLUSIVE"


def test_run_truncated_differential_surfaces_truncation_reason():
    answers = {
        ("traceroute", "base"): [trace_row("ACCEPTED")],
        ("traceroute", "prop"): [trace_row("NO_ROUTE")],
        ("differentialReachability", "prop"): [
            multi_differential_row(["NO_ROUTE"], ["ACCEPTED"], snapshot_total=12, reference_total=1)
        ],
    }
    client = FakeClient(answers=answers)
    store = EvidenceStore()
    result = run_mandatory_assessment(client, store, BASE, PROP, _intent())
    assert result.flow_comparisons[0].classification == "UNKNOWN"
    assert result.verdict == "INCONCLUSIVE"
    assert any("truncation" in reason for reason in result.inconclusive_reasons)
