"""Deterministic Stage C verification tests (no Batfish, no model calls).

``FakeClient`` stands in for Batfish with canned answers; the EvidenceStore
is real. Stage A results are constructed by hand so every baseline-reference
rule is exercised directly.
"""

from __future__ import annotations

import json

from netops_lens.evidence import EvidenceStore
from netops_lens.models import (
    AssessmentResult,
    FlowComparison,
    FlowSpec,
    Intent,
    SnapshotHealth,
    SnapshotRef,
)
from netops_lens.verify import verify_candidate
from tests._fakes import (
    FakeClient,
    differential_row,
    flow_dict,
    healthy_records,
    multi_differential_row,
    trace_row,
)

START = "@enter(r1[GigabitEthernet0/1])"
BASE = SnapshotRef(name="base", path="lab/baseline")
CAND_NAME = "run-candidate-c-01"
CAND = SnapshotRef(name=CAND_NAME, path="runs/r1/candidate-c-01")


def _web_flow() -> FlowSpec:
    return FlowSpec(
        flow_id="web",
        src_ip="192.0.2.10",
        dst_ip="198.51.100.1",
        protocol="TCP",
        dst_port=1433,
        start_location=START,
    )


def _ssh_flow() -> FlowSpec:
    return FlowSpec(
        flow_id="ssh",
        src_ip="192.0.2.10",
        dst_ip="198.51.100.1",
        protocol="TCP",
        dst_port=22,
        start_location=START,
    )


def _intent() -> Intent:
    return Intent(
        version=1,
        description="t",
        must_reach=[_web_flow()],
        must_not_reach=[_ssh_flow()],
    )


def _comparison(
    flow_id: str,
    kind: str,
    base: str,
    prop: str,
    classification: str,
) -> FlowComparison:
    return FlowComparison(
        flow_id=flow_id,
        kind=kind,  # type: ignore[arg-type]
        baseline_reach=base,  # type: ignore[arg-type]
        proposed_reach=prop,  # type: ignore[arg-type]
        classification=classification,  # type: ignore[arg-type]
    )


def _stage_a(
    *,
    base_health: str = "OK",
    comparisons: list | None = None,
    health_order: tuple[str, ...] = ("base", "prop"),
    verdict: str = "REGRESSION_DETECTED",
) -> AssessmentResult:
    def _health(name: str) -> SnapshotHealth:
        if name == "base" and base_health != "OK":
            return SnapshotHealth(snapshot=name, status="NOT_OK", reasons=("parse failed",))
        return SnapshotHealth(snapshot=name, status="OK")

    if comparisons is None:
        comparisons = [
            _comparison("web", "must_reach", "REACHABLE", "UNREACHABLE", "REGRESSION"),
            _comparison("ssh", "must_not_reach", "UNREACHABLE", "UNREACHABLE", "NO_CHANGE_OK"),
        ]
    return AssessmentResult(
        verdict=verdict,  # type: ignore[arg-type]
        flow_comparisons=tuple(comparisons),
        health=tuple(_health(name) for name in health_order),
    )


def _web_row(disposition: str) -> dict:
    return trace_row(disposition, flow=flow_dict(proto="TCP", dport=1433))


def _ssh_row(disposition: str) -> dict:
    return trace_row(disposition, flow=flow_dict(proto="TCP", dport=22))


def _web_diff(snapshot_disp: str, reference_disp: str) -> dict:
    return differential_row(snapshot_disp, reference_disp, flow=flow_dict(proto="TCP", dport=1433))


def _ssh_diff(snapshot_disp: str, reference_disp: str) -> dict:
    return differential_row(snapshot_disp, reference_disp, flow=flow_dict(proto="TCP", dport=22))


def _client(
    *,
    tracerows: list,
    diffrows: list,
    health=None,
    failures: set | None = None,
) -> FakeClient:
    return FakeClient(
        answers={
            ("traceroute", CAND_NAME): tracerows,
            ("differentialReachability", CAND_NAME): diffrows,
        },
        health=health if health is not None else healthy_records(),
        failures=failures or set(),
    )


def _check_names(result) -> list[str]:
    return [check.name for check in result.checks]


def test_verified_repair_holds_and_checks_every_flow():
    store = EvidenceStore()
    client = _client(
        tracerows=[_web_row("ACCEPTED"), _ssh_row("DENIED_IN")],
        diffrows=[_web_diff("ACCEPTED", "ACCEPTED"), _ssh_diff("DENIED_IN", "DENIED_IN")],
    )
    result = verify_candidate(
        client, store, candidate_id="c-01", baseline_ref=BASE, candidate_ref=CAND,
        intent=_intent(), stage_a=_stage_a(),
    )
    assert result.status == "VERIFIED"
    assert result.candidate_snapshot == CAND_NAME
    assert result.reasons == ()
    assert _check_names(result) == [
        "candidate_health",
        "intent:web",
        "differential:web",
        "no_regression:web",
        "intent:ssh",
        "differential:ssh",
        "no_regression:ssh",
    ]
    assert all(check.outcome == "pass" for check in result.checks)
    assert client.asked("traceroute", CAND_NAME) == 2
    assert client.asked("differentialReachability", CAND_NAME) == 2
    # Differential was queried baseline-first: the reference is the baseline.
    assert ("differentialReachability", CAND_NAME, "base") in client.calls
    # Evidence is the ordered dedup union of per-check evidence, all minted here.
    flat: list[str] = []
    for check in result.checks:
        flat.extend(check.evidence_ids)
    assert tuple(dict.fromkeys(flat)) == result.evidence_ids
    assert result.evidence_ids == ("ev-0001", "ev-0002", "ev-0003", "ev-0004", "ev-0005")
    for check in result.checks:
        for evidence_id in check.evidence_ids:
            record = store.get(evidence_id)
            assert record is not None
            expected_flow = check.name.split(":", 1)[-1]
            assert record.flow_id in (None, expected_flow)
            assert CAND_NAME in record.snapshots


def test_rejected_when_target_still_broken():
    store = EvidenceStore()
    client = _client(
        tracerows=[_web_row("NO_ROUTE"), _ssh_row("DENIED_IN")],
        diffrows=[_web_diff("NO_ROUTE", "ACCEPTED"), _ssh_diff("DENIED_IN", "DENIED_IN")],
    )
    result = verify_candidate(
        client, store, candidate_id="c-01", baseline_ref=BASE, candidate_ref=CAND,
        intent=_intent(), stage_a=_stage_a(),
    )
    assert result.status == "REJECTED"
    by_name = {check.name: check for check in result.checks}
    assert by_name["intent:web"].outcome == "fail"
    assert by_name["no_regression:web"].outcome == "fail"
    assert by_name["intent:ssh"].outcome == "pass"
    assert by_name["no_regression:ssh"].outcome == "pass"
    assert result.reasons != ()


def test_rejected_when_candidate_breaks_protected_flow():
    store = EvidenceStore()
    client = _client(
        tracerows=[_web_row("ACCEPTED"), _ssh_row("ACCEPTED")],
        diffrows=[_web_diff("ACCEPTED", "ACCEPTED"), _ssh_diff("ACCEPTED", "DENIED_IN")],
    )
    result = verify_candidate(
        client, store, candidate_id="c-01", baseline_ref=BASE, candidate_ref=CAND,
        intent=_intent(), stage_a=_stage_a(),
    )
    assert result.status == "REJECTED"
    by_name = {check.name: check for check in result.checks}
    assert by_name["intent:web"].outcome == "pass"
    assert by_name["intent:ssh"].outcome == "fail"
    assert by_name["no_regression:ssh"].outcome == "fail"


def test_rejected_when_preexisting_violation_persists():
    stage_a = _stage_a(
        comparisons=[
            _comparison("web", "must_reach", "REACHABLE", "UNREACHABLE", "REGRESSION"),
            _comparison(
                "ssh", "must_not_reach", "REACHABLE", "REACHABLE", "PRE_EXISTING_VIOLATION"
            ),
        ]
    )
    store = EvidenceStore()
    client = _client(
        tracerows=[_web_row("ACCEPTED"), _ssh_row("ACCEPTED")],
        diffrows=[_web_diff("ACCEPTED", "ACCEPTED"), _ssh_diff("ACCEPTED", "ACCEPTED")],
    )
    result = verify_candidate(
        client, store, candidate_id="c-01", baseline_ref=BASE, candidate_ref=CAND,
        intent=_intent(), stage_a=stage_a,
    )
    assert result.status == "REJECTED"
    by_name = {check.name: check for check in result.checks}
    assert by_name["intent:web"].outcome == "pass"
    assert by_name["no_regression:web"].outcome == "pass"
    assert by_name["intent:ssh"].outcome == "fail"
    assert by_name["no_regression:ssh"].outcome == "fail"
    assert "PRE_EXISTING_VIOLATION" in by_name["no_regression:ssh"].detail


def test_verified_when_regression_and_preexisting_both_fixed():
    stage_a = _stage_a(
        comparisons=[
            _comparison("web", "must_reach", "REACHABLE", "UNREACHABLE", "REGRESSION"),
            _comparison(
                "ssh", "must_not_reach", "REACHABLE", "REACHABLE", "PRE_EXISTING_VIOLATION"
            ),
        ]
    )
    store = EvidenceStore()
    client = _client(
        tracerows=[_web_row("ACCEPTED"), _ssh_row("DENIED_IN")],
        diffrows=[_web_diff("ACCEPTED", "ACCEPTED"), _ssh_diff("DENIED_IN", "ACCEPTED")],
    )
    result = verify_candidate(
        client, store, candidate_id="c-01", baseline_ref=BASE, candidate_ref=CAND,
        intent=_intent(), stage_a=stage_a,
    )
    assert result.status == "VERIFIED"
    by_name = {check.name: check for check in result.checks}
    assert "IMPROVEMENT" in by_name["no_regression:ssh"].detail


def test_unverifiable_when_differential_incomplete():
    store = EvidenceStore()
    truncated = multi_differential_row(
        ["ACCEPTED"], ["ACCEPTED"], snapshot_total=5, reference_total=1,
        flow=flow_dict(proto="TCP", dport=1433),
    )
    client = _client(
        tracerows=[_web_row("ACCEPTED"), _ssh_row("DENIED_IN")],
        diffrows=[truncated, _ssh_diff("DENIED_IN", "DENIED_IN")],
    )
    result = verify_candidate(
        client, store, candidate_id="c-01", baseline_ref=BASE, candidate_ref=CAND,
        intent=_intent(), stage_a=_stage_a(),
    )
    assert result.status == "UNVERIFIABLE"
    by_name = {check.name: check for check in result.checks}
    assert by_name["intent:web"].outcome == "pass"
    assert by_name["differential:web"].outcome == "unknown"
    assert by_name["no_regression:web"].outcome == "unknown"
    assert by_name["no_regression:ssh"].outcome == "pass"


def test_unverifiable_when_differential_conflicts_with_directs():
    store = EvidenceStore()
    client = _client(
        tracerows=[_web_row("ACCEPTED"), _ssh_row("DENIED_IN")],
        diffrows=[_web_diff("ACCEPTED", "NO_ROUTE"), _ssh_diff("DENIED_IN", "DENIED_IN")],
    )
    result = verify_candidate(
        client, store, candidate_id="c-01", baseline_ref=BASE, candidate_ref=CAND,
        intent=_intent(), stage_a=_stage_a(),
    )
    assert result.status == "UNVERIFIABLE"
    by_name = {check.name: check for check in result.checks}
    assert by_name["intent:web"].outcome == "pass"
    assert by_name["differential:web"].outcome == "pass"
    assert by_name["no_regression:web"].outcome == "unknown"


def test_fail_plus_unknown_is_unverifiable_not_rejected():
    store = EvidenceStore()
    truncated = multi_differential_row(
        ["DENIED_IN"], ["DENIED_IN"], snapshot_total=4, reference_total=1,
        flow=flow_dict(proto="TCP", dport=22),
    )
    client = _client(
        tracerows=[_web_row("NO_ROUTE"), _ssh_row("DENIED_IN")],
        diffrows=[_web_diff("NO_ROUTE", "ACCEPTED"), truncated],
    )
    result = verify_candidate(
        client, store, candidate_id="c-01", baseline_ref=BASE, candidate_ref=CAND,
        intent=_intent(), stage_a=_stage_a(),
    )
    assert result.status == "UNVERIFIABLE"
    by_name = {check.name: check for check in result.checks}
    assert by_name["intent:web"].outcome == "fail"
    assert by_name["no_regression:ssh"].outcome == "unknown"


def test_empty_differential_with_equal_directs_verifies():
    store = EvidenceStore()
    client = _client(
        tracerows=[_web_row("ACCEPTED"), _ssh_row("DENIED_IN")],
        diffrows=[],
    )
    result = verify_candidate(
        client, store, candidate_id="c-01", baseline_ref=BASE, candidate_ref=CAND,
        intent=_intent(), stage_a=_stage_a(),
    )
    assert result.status == "VERIFIED"


def test_empty_differential_cannot_rescue_changed_directs():
    # Directs show REACHABLE -> UNREACHABLE but the empty differential does
    # not corroborate the change: reconciliation is UNKNOWN, so despite the
    # definite intent failure the complete result is UNVERIFIABLE, never
    # REJECTED (and never VERIFIED on direct evidence alone).
    stage_a = _stage_a(
        comparisons=[
            _comparison("web", "must_reach", "REACHABLE", "REACHABLE", "NO_CHANGE_OK"),
            _comparison("ssh", "must_not_reach", "UNREACHABLE", "UNREACHABLE", "NO_CHANGE_OK"),
        ]
    )
    store = EvidenceStore()
    client = _client(
        tracerows=[_web_row("NO_ROUTE"), _ssh_row("DENIED_IN")],
        diffrows=[],
    )
    result = verify_candidate(
        client, store, candidate_id="c-01", baseline_ref=BASE, candidate_ref=CAND,
        intent=_intent(), stage_a=stage_a,
    )
    assert result.status == "UNVERIFIABLE"
    by_name = {check.name: check for check in result.checks}
    assert by_name["intent:web"].outcome == "fail"
    assert by_name["no_regression:web"].outcome == "unknown"
    assert "does not corroborate" in by_name["no_regression:web"].detail


def test_candidate_health_not_ok_is_unverifiable_without_flow_checks():
    from netops_lens.batfish_client import HealthRecords

    failing = HealthRecords(
        parse_status=({"File_Name": "configs/r1.cfg", "Status": "FAILED"},),
        init_issues=(),
        nodes=({"Node": "r1"},),
    )
    store = EvidenceStore()
    client = _client(tracerows=[], diffrows=[], health=failing)
    result = verify_candidate(
        client, store, candidate_id="c-01", baseline_ref=BASE, candidate_ref=CAND,
        intent=_intent(), stage_a=_stage_a(),
    )
    assert result.status == "UNVERIFIABLE"
    assert _check_names(result) == [
        "candidate_health",
        "intent:web",
        "differential:web",
        "no_regression:web",
        "intent:ssh",
        "differential:ssh",
        "no_regression:ssh",
    ]
    assert all(c.outcome == "unknown" for c in result.checks)
    assert all(c.evidence_ids == () for c in result.checks[1:])
    # K-03: the real minted health evidence stays attached to the check.
    assert result.checks[0].evidence_ids == tuple(store.ids())
    assert len(result.checks[0].evidence_ids) == 1
    record = store.get(result.checks[0].evidence_ids[0])
    assert record is not None
    assert record.snapshots == [CAND_NAME]
    assert result.evidence_ids == result.checks[0].evidence_ids
    assert client.asked("traceroute", CAND_NAME) == 0
    assert client.asked("differentialReachability", CAND_NAME) == 0


def test_candidate_health_query_error_is_unverifiable():
    store = EvidenceStore()
    client = _client(tracerows=[], diffrows=[], failures={("__health__", CAND_NAME)})
    result = verify_candidate(
        client, store, candidate_id="c-01", baseline_ref=BASE, candidate_ref=CAND,
        intent=_intent(), stage_a=_stage_a(),
    )
    assert result.status == "UNVERIFIABLE"
    assert _check_names(result) == [
        "candidate_health",
        "intent:web",
        "differential:web",
        "no_regression:web",
        "intent:ssh",
        "differential:ssh",
        "no_regression:ssh",
    ]
    assert all(c.outcome == "unknown" for c in result.checks)


def test_missing_baseline_health_is_unverifiable():
    stage_a = _stage_a(health_order=("prop",))
    store = EvidenceStore()
    client = _client(tracerows=[], diffrows=[])
    before = store.export_json()
    result = verify_candidate(
        client, store, candidate_id="c-01", baseline_ref=BASE, candidate_ref=CAND,
        intent=_intent(), stage_a=stage_a,
    )
    assert result.status == "UNVERIFIABLE"
    assert store.export_json() == before  # no candidate queries ran
    assert _check_names(result) == [
        "candidate_health",
        "intent:web",
        "differential:web",
        "no_regression:web",
        "intent:ssh",
        "differential:ssh",
        "no_regression:ssh",
    ]
    assert all(c.outcome == "unknown" for c in result.checks)
    assert all(c.evidence_ids == () for c in result.checks)


def test_baseline_health_not_ok_is_unverifiable():
    store = EvidenceStore()
    client = _client(tracerows=[], diffrows=[])
    result = verify_candidate(
        client, store, candidate_id="c-01", baseline_ref=BASE, candidate_ref=CAND,
        intent=_intent(), stage_a=_stage_a(base_health="NOT_OK"),
    )
    assert result.status == "UNVERIFIABLE"
    assert client.asked("traceroute", CAND_NAME) == 0


def test_health_tuple_order_does_not_matter():
    store = EvidenceStore()
    client = _client(
        tracerows=[_web_row("ACCEPTED"), _ssh_row("DENIED_IN")],
        diffrows=[_web_diff("ACCEPTED", "ACCEPTED"), _ssh_diff("DENIED_IN", "DENIED_IN")],
    )
    result = verify_candidate(
        client, store, candidate_id="c-01", baseline_ref=BASE, candidate_ref=CAND,
        intent=_intent(), stage_a=_stage_a(health_order=("prop", "base")),
    )
    assert result.status == "VERIFIED"


def test_missing_baseline_flow_comparison_is_unverifiable():
    stage_a = _stage_a(
        comparisons=[
            _comparison("web", "must_reach", "REACHABLE", "UNREACHABLE", "REGRESSION"),
        ]
    )
    store = EvidenceStore()
    client = _client(tracerows=[], diffrows=[])
    result = verify_candidate(
        client, store, candidate_id="c-01", baseline_ref=BASE, candidate_ref=CAND,
        intent=_intent(), stage_a=stage_a,
    )
    assert result.status == "UNVERIFIABLE"
    assert client.asked("traceroute", CAND_NAME) == 0


def test_duplicate_baseline_flow_comparison_is_unverifiable():
    stage_a = _stage_a(
        comparisons=[
            _comparison("web", "must_reach", "REACHABLE", "UNREACHABLE", "REGRESSION"),
            _comparison("web", "must_reach", "REACHABLE", "UNREACHABLE", "REGRESSION"),
            _comparison("ssh", "must_not_reach", "UNREACHABLE", "UNREACHABLE", "NO_CHANGE_OK"),
        ]
    )
    store = EvidenceStore()
    client = _client(tracerows=[], diffrows=[])
    result = verify_candidate(
        client, store, candidate_id="c-01", baseline_ref=BASE, candidate_ref=CAND,
        intent=_intent(), stage_a=stage_a,
    )
    assert result.status == "UNVERIFIABLE"


def test_unknown_baseline_reachability_is_unverifiable():
    stage_a = _stage_a(
        comparisons=[
            _comparison("web", "must_reach", "UNKNOWN", "UNKNOWN", "UNKNOWN"),
            _comparison("ssh", "must_not_reach", "UNREACHABLE", "UNREACHABLE", "NO_CHANGE_OK"),
        ]
    )
    store = EvidenceStore()
    client = _client(tracerows=[], diffrows=[])
    result = verify_candidate(
        client, store, candidate_id="c-01", baseline_ref=BASE, candidate_ref=CAND,
        intent=_intent(), stage_a=stage_a,
    )
    assert result.status == "UNVERIFIABLE"


def test_kind_mismatched_comparison_is_unverifiable():
    stage_a = _stage_a(
        comparisons=[
            _comparison("web", "must_not_reach", "UNREACHABLE", "UNREACHABLE", "NO_CHANGE_OK"),
            _comparison("ssh", "must_not_reach", "UNREACHABLE", "UNREACHABLE", "NO_CHANGE_OK"),
        ]
    )
    store = EvidenceStore()
    client = _client(tracerows=[], diffrows=[])
    result = verify_candidate(
        client, store, candidate_id="c-01", baseline_ref=BASE, candidate_ref=CAND,
        intent=_intent(), stage_a=stage_a,
    )
    assert result.status == "UNVERIFIABLE"


def test_baseline_read_from_comparisons_not_findings_or_verdict():
    # Findings claim nothing usable and the verdict disagrees with the data;
    # verification must follow comparisons/health only and still VERIFY.
    stage_a = _stage_a(verdict="INCONCLUSIVE")
    dumped_before = stage_a.model_dump_json()
    store = EvidenceStore()
    client = _client(
        tracerows=[_web_row("ACCEPTED"), _ssh_row("DENIED_IN")],
        diffrows=[_web_diff("ACCEPTED", "ACCEPTED"), _ssh_diff("DENIED_IN", "DENIED_IN")],
    )
    result = verify_candidate(
        client, store, candidate_id="c-01", baseline_ref=BASE, candidate_ref=CAND,
        intent=_intent(), stage_a=stage_a,
    )
    assert result.status == "VERIFIED"
    assert stage_a.model_dump_json() == dumped_before
    assert stage_a.verdict == "INCONCLUSIVE"


def test_stage_a_immutable_across_failed_verification():
    stage_a = _stage_a()
    dumped_before = stage_a.model_dump_json()
    store = EvidenceStore()
    client = _client(
        tracerows=[_web_row("NO_ROUTE"), _ssh_row("ACCEPTED")],
        diffrows=[_web_diff("NO_ROUTE", "ACCEPTED"), _ssh_diff("ACCEPTED", "DENIED_IN")],
    )
    result = verify_candidate(
        client, store, candidate_id="c-01", baseline_ref=BASE, candidate_ref=CAND,
        intent=_intent(), stage_a=stage_a,
    )
    assert result.status == "REJECTED"
    assert stage_a.model_dump_json() == dumped_before


def test_traceroute_tool_error_is_unknown_not_guessed():
    store = EvidenceStore()
    client = _client(tracerows=[], diffrows=[], failures={("traceroute", CAND_NAME)})
    result = verify_candidate(
        client, store, candidate_id="c-01", baseline_ref=BASE, candidate_ref=CAND,
        intent=_intent(), stage_a=_stage_a(),
    )
    assert result.status == "UNVERIFIABLE"
    by_name = {check.name: check for check in result.checks}
    assert by_name["intent:web"].outcome == "unknown"
    assert by_name["intent:ssh"].outcome == "unknown"


def test_differential_tool_error_is_unknown():
    store = EvidenceStore()
    client = _client(
        tracerows=[_web_row("ACCEPTED"), _ssh_row("DENIED_IN")],
        diffrows=[],
        failures={("differentialReachability", CAND_NAME)},
    )
    result = verify_candidate(
        client, store, candidate_id="c-01", baseline_ref=BASE, candidate_ref=CAND,
        intent=_intent(), stage_a=_stage_a(),
    )
    assert result.status == "UNVERIFIABLE"
    by_name = {check.name: check for check in result.checks}
    assert by_name["differential:web"].outcome == "unknown"
    assert by_name["no_regression:web"].outcome == "unknown"


def test_unexpected_tool_exception_leaves_check_unknown_without_evidence():
    from netops_lens.batfish_client import BatfishClient

    class _ExplodingClient(FakeClient):
        def ask(self, question, snapshot, reference_snapshot=None, **params):
            if question == "traceroute":
                raise RuntimeError("transport blew up")
            return super().ask(question, snapshot, reference_snapshot, **params)

    assert issubclass(_ExplodingClient, BatfishClient)
    store = EvidenceStore()
    client = _ExplodingClient(
        answers={("differentialReachability", CAND_NAME): []},
    )
    result = verify_candidate(
        client, store, candidate_id="c-01", baseline_ref=BASE, candidate_ref=CAND,
        intent=_intent(), stage_a=_stage_a(),
    )
    assert result.status == "UNVERIFIABLE"
    by_name = {check.name: check for check in result.checks}
    assert by_name["intent:web"].outcome == "unknown"
    assert by_name["intent:web"].evidence_ids == ()


def test_evidence_ids_continue_monotonically_in_shared_store():
    store = EvidenceStore()
    seed = store.record(tool="check_intent", snapshots=["base"], flow_id="web", details={})
    assert seed == "ev-0001"
    before = store.get("ev-0001")
    client = _client(
        tracerows=[_web_row("ACCEPTED"), _ssh_row("DENIED_IN")],
        diffrows=[_web_diff("ACCEPTED", "ACCEPTED"), _ssh_diff("DENIED_IN", "DENIED_IN")],
    )
    first = verify_candidate(
        client, store, candidate_id="c-01", baseline_ref=BASE, candidate_ref=CAND,
        intent=_intent(), stage_a=_stage_a(),
    )
    second = verify_candidate(
        client, store, candidate_id="c-02", baseline_ref=BASE, candidate_ref=CAND,
        intent=_intent(), stage_a=_stage_a(),
    )
    assert first.status == "VERIFIED"
    assert second.status == "VERIFIED"
    assert first.evidence_ids[0] == "ev-0002"
    assert second.evidence_ids[0] == "ev-0007"
    assert len(set(first.evidence_ids) | set(second.evidence_ids)) == len(
        first.evidence_ids
    ) + len(second.evidence_ids)
    assert store.get("ev-0001") == before
    by_name = {check.name: check for check in first.checks}
    assert set(by_name["no_regression:web"].evidence_ids) == set(
        by_name["intent:web"].evidence_ids
    ) | set(by_name["differential:web"].evidence_ids)


def test_result_has_snapshot_name_only_and_no_absolute_paths():
    store = EvidenceStore()
    client = _client(
        tracerows=[_web_row("ACCEPTED"), _ssh_row("DENIED_IN")],
        diffrows=[_web_diff("ACCEPTED", "ACCEPTED"), _ssh_diff("DENIED_IN", "DENIED_IN")],
    )
    result = verify_candidate(
        client, store, candidate_id="c-01", baseline_ref=BASE, candidate_ref=CAND,
        intent=_intent(), stage_a=_stage_a(),
    )
    assert result.candidate_snapshot == CAND_NAME
    blob = result.model_dump_json()
    assert "runs/" not in blob
    assert "/tmp" not in blob
    assert json.loads(blob)["candidate_snapshot"] == CAND_NAME


def test_candidate_equal_to_baseline_rejected_before_tool_calls():
    store = EvidenceStore()
    client = _client(
        tracerows=[_web_row("ACCEPTED"), _ssh_row("DENIED_IN")],
        diffrows=[_web_diff("ACCEPTED", "ACCEPTED"), _ssh_diff("DENIED_IN", "DENIED_IN")],
    )
    same_as_baseline = SnapshotRef(name="base", path="lab/baseline")
    result = verify_candidate(
        client, store, candidate_id="c-01", baseline_ref=BASE, candidate_ref=same_as_baseline,
        intent=_intent(), stage_a=_stage_a(),
    )
    assert result.status == "UNVERIFIABLE"
    assert result.candidate_snapshot is None
    assert client.asked("traceroute", "base") == 0
    assert client.asked("differentialReachability", "base") == 0
    assert _check_names(result)[0] == "candidate_health"
    assert all(c.outcome == "unknown" for c in result.checks)


def test_non_canonical_candidate_name_rejected_before_tool_calls():
    store = EvidenceStore()
    client = _client(tracerows=[], diffrows=[])
    bogus = SnapshotRef(name="proposed", path="lab/proposed")
    result = verify_candidate(
        client, store, candidate_id="c-01", baseline_ref=BASE, candidate_ref=bogus,
        intent=_intent(), stage_a=_stage_a(),
    )
    assert result.status == "UNVERIFIABLE"
    assert result.candidate_snapshot is None
    assert client.calls == []
    assert any("canonical" in check.detail for check in result.checks)


def test_empty_intent_is_unverifiable():
    store = EvidenceStore()
    client = _client(tracerows=[], diffrows=[])
    empty = Intent(version=1, description="nothing declared")
    result = verify_candidate(
        client, store, candidate_id="c-01", baseline_ref=BASE, candidate_ref=CAND,
        intent=empty, stage_a=_stage_a(),
    )
    assert result.status == "UNVERIFIABLE"
    assert result.checks == ()
    assert client.asked("traceroute", CAND_NAME) == 0
