"""Evidence store + four-check validation tests (no Batfish, no LLM)."""

from __future__ import annotations

import json

from netops_lens.evidence import EvidenceStore, validate_finding
from netops_lens.models import ClaimType, Finding, FlowSpec, SnapshotRef
from netops_lens.tools import check_intent
from tests._fakes import FakeClient, multi_trace_row, trace_row


def _finding(**overrides) -> Finding:
    payload = {
        "finding_id": "f-0001",
        "claim_type": ClaimType.INTENT_VIOLATED,
        "flow_id": "app-to-db-icmp",
        "statement": "flow violated",
        "evidence_ids": ["ev-0001"],
        "severity": "error",
    }
    payload.update(overrides)
    return Finding(**payload)


def _store_with_check(
    *,
    snapshot: str = "proposed",
    flow_id: str | None = "app-to-db-icmp",
    disposition: str | None = "NO_ROUTE",
) -> tuple[EvidenceStore, str]:
    store = EvidenceStore()
    evidence_id = store.record(
        tool="check_intent",
        snapshots=[snapshot],
        flow_id=flow_id,
        disposition=disposition,
        details={"tool_status": "ok"},
    )
    return store, evidence_id


def test_minting_sequence_format_export():
    store = EvidenceStore()
    first = store.record(tool="t", snapshots=["s"])
    second = store.record(tool="t", snapshots=["s"])
    assert (first, second) == ("ev-0001", "ev-0002")
    assert len(store) == 2
    assert store.get("ev-0001") is not None
    assert store.get("ev-9999") is None
    exported = json.loads(store.export_json())
    assert set(exported) == {"ev-0001", "ev-0002"}
    assert exported["ev-0001"]["created_order"] == 1


def test_valid_finding_passes_all_checks():
    store, evidence_id = _store_with_check()
    finding = _finding(evidence_ids=[evidence_id])
    ok, failed = validate_finding(
        finding,
        store,
        allowed_snapshots={"baseline", "proposed"},
        kind="must_reach",
        subject_snapshot="proposed",
    )
    assert (ok, failed) == (True, None)


def test_existence_check_rejects_dangling_id():
    store, _ = _store_with_check()
    finding = _finding(evidence_ids=["ev-9999"])
    ok, failed = validate_finding(
        finding,
        store,
        allowed_snapshots={"proposed"},
        kind="must_reach",
        subject_snapshot="proposed",
    )
    assert (ok, failed) == (False, "existence")


def test_flow_identity_rejects_unrelated_evidence():
    store, _ = _store_with_check(flow_id="other-flow")
    finding = _finding(evidence_ids=["ev-0001"])
    ok, failed = validate_finding(
        finding,
        store,
        allowed_snapshots={"proposed"},
        kind="must_reach",
        subject_snapshot="proposed",
    )
    assert (ok, failed) == (False, "flow_identity")


def test_snapshot_identity_rejects_wrong_snapshot():
    store, _ = _store_with_check(snapshot="baseline")
    finding = _finding(evidence_ids=["ev-0001"])
    ok, failed = validate_finding(
        finding,
        store,
        allowed_snapshots={"proposed"},
        kind="must_reach",
        subject_snapshot="proposed",
    )
    assert (ok, failed) == (False, "snapshot_identity")


def test_disposition_support_rejects_contradicting_evidence():
    store, _ = _store_with_check(disposition="ACCEPTED")
    finding = _finding(evidence_ids=["ev-0001"])
    ok, failed = validate_finding(
        finding,
        store,
        allowed_snapshots={"proposed"},
        kind="must_reach",
        subject_snapshot="proposed",
    )
    assert (ok, failed) == (False, "disposition_support")


def test_health_finding_validates_against_health_records():
    store = EvidenceStore()
    evidence_id = store.record(
        tool="get_snapshot_health",
        snapshots=["baseline"],
        details={"tool_status": "ok"},
    )
    finding = _finding(
        claim_type=ClaimType.SNAPSHOT_HEALTH,
        flow_id=None,
        evidence_ids=[evidence_id],
        statement="snapshot 'baseline' health OK",
        severity="info",
    )
    ok, failed = validate_finding(
        finding, store, allowed_snapshots={"baseline"}, subject_snapshot="baseline"
    )
    assert (ok, failed) == (True, None)


def test_health_finding_rejects_flow_records():
    store, _ = _store_with_check()
    finding = _finding(
        claim_type=ClaimType.SNAPSHOT_HEALTH,
        flow_id=None,
        evidence_ids=["ev-0001"],
        statement="snapshot health",
        severity="info",
    )
    ok, failed = validate_finding(
        finding, store, allowed_snapshots={"proposed"}, subject_snapshot="proposed"
    )
    assert (ok, failed) == (False, "flow_identity")


def _route_absent_finding(evidence_id):
    return _finding(
        claim_type=ClaimType.ROUTE_ABSENT,
        flow_id=None,
        evidence_ids=[evidence_id],
        statement="no route to 203.0.113.0/24 on r1",
        severity="info",
    )


def test_route_absent_accepts_empty_ok_table():
    store = EvidenceStore()
    evidence_id = store.record(
        tool="get_routes",
        snapshots=["s"],
        details={
            "tool_status": "ok",
            "node": "r1",
            "prefix": "203.0.113.0/24",
            "route_found": False,
            "route_count": 0,
            "routes": [],
        },
    )
    ok, failed = validate_finding(
        _route_absent_finding(evidence_id), store, allowed_snapshots={"s"}
    )
    assert (ok, failed) == (True, None)


def test_route_absent_rejects_error_records():
    store = EvidenceStore()
    evidence_id = store.record(
        tool="get_routes",
        snapshots=["s"],
        details={"tool_status": "error", "error": "unknown node 'r9'"},
    )
    ok, failed = validate_finding(
        _route_absent_finding(evidence_id), store, allowed_snapshots={"s"}
    )
    assert (ok, failed) == (False, "disposition_support")


def test_route_absent_rejects_malformed_empty_results():
    store = EvidenceStore()
    malformed = [
        # route_found not explicitly False
        {"tool_status": "ok", "node": "r1", "prefix": None, "route_count": 0, "routes": []},
        # non-empty table claimed absent
        {
            "tool_status": "ok",
            "node": "r1",
            "prefix": None,
            "route_found": False,
            "route_count": 1,
            "routes": [{"Network": "x"}],
        },
        # missing node identity
        {
            "tool_status": "ok",
            "prefix": None,
            "route_found": False,
            "route_count": 0,
            "routes": [],
        },
        # missing prefix key
        {"tool_status": "ok", "node": "r1", "route_found": False, "route_count": 0, "routes": []},
    ]
    for details in malformed:
        evidence_id = store.record(tool="get_routes", snapshots=["s"], details=details)
        ok, failed = validate_finding(
            _route_absent_finding(evidence_id), store, allowed_snapshots={"s"}
        )
        assert (ok, failed) == (False, "disposition_support"), details


def _icmp_flow() -> FlowSpec:
    return FlowSpec(
        flow_id="f-denied-split",
        src_ip="192.0.2.10",
        dst_ip="198.51.100.1",
        protocol="ICMP",
        start_location="@enter(r1[GigabitEthernet0/1])",
    )


def test_normalized_reachability_covers_split_denied_family():
    """N-01: a unanimous mixed-DENIED trace set normalizes to UNREACHABLE and
    supports REACHABILITY_CHANGED alongside an ACCEPTED baseline."""
    flow = _icmp_flow()
    store = EvidenceStore()
    answers = {
        ("traceroute", "base"): [trace_row("ACCEPTED")],
        ("traceroute", "prop"): [multi_trace_row(["DENIED_IN", "DENIED_OUT"])],
    }
    client = FakeClient(answers=answers)
    base = SnapshotRef(name="base", path="b")
    prop = SnapshotRef(name="prop", path="p")
    base_result, base_outcome = check_intent(client, store, flow, base)
    prop_result, prop_outcome = check_intent(client, store, flow, prop)
    assert base_outcome.reachability == "REACHABLE"
    assert base_result.details["batfish_disposition"] == "ACCEPTED"
    assert prop_outcome.reachability == "UNREACHABLE"
    # No representative raw disposition is invented for the mixed set.
    assert prop_result.details["batfish_disposition"] is None
    assert prop_result.details["raw_dispositions"] == ["DENIED_IN", "DENIED_OUT"]
    assert prop_result.details["reachability"] == "UNREACHABLE"
    finding = _finding(
        claim_type=ClaimType.REACHABILITY_CHANGED,
        flow_id=flow.flow_id,
        evidence_ids=[base_result.evidence_id, prop_result.evidence_id],
    )
    ok, failed = validate_finding(
        finding, store, allowed_snapshots={"base", "prop"}, subject_snapshot="prop"
    )
    assert (ok, failed) == (True, None)


def test_different_raw_denied_sets_share_normalized_reachability():
    """N-01: DENIED_IN-only and mixed DENIED_IN/DENIED_OUT direct sets carry
    the same normalized UNREACHABLE and each independently supports an
    UNREACHABLE finding."""
    flow = _icmp_flow()
    store = EvidenceStore()
    answers = {
        ("traceroute", "s1"): [trace_row("DENIED_IN")],
        ("traceroute", "s2"): [multi_trace_row(["DENIED_IN", "DENIED_OUT"])],
    }
    client = FakeClient(answers=answers)
    single, _ = check_intent(client, store, flow, SnapshotRef(name="s1", path="b"))
    mixed, _ = check_intent(client, store, flow, SnapshotRef(name="s2", path="b"))
    assert single.details["reachability"] == mixed.details["reachability"] == "UNREACHABLE"
    assert single.details["batfish_disposition"] == "DENIED_IN"
    assert mixed.details["batfish_disposition"] is None
    for evidence_id in (single.evidence_id, mixed.evidence_id):
        finding = _finding(
            claim_type=ClaimType.INTENT_SATISFIED,
            flow_id=flow.flow_id,
            evidence_ids=[evidence_id],
        )
        ok, failed = validate_finding(
            finding,
            store,
            allowed_snapshots={"s1", "s2"},
            kind="must_not_reach",
            subject_snapshot="prop",
        )
        # Subject scoping still applies: neither record is on "prop".
        assert (ok, failed) == (False, "disposition_support")
    finding = _finding(
        claim_type=ClaimType.INTENT_SATISFIED,
        flow_id=flow.flow_id,
        evidence_ids=[mixed.evidence_id],
    )
    ok, failed = validate_finding(
        finding, store, allowed_snapshots={"s1", "s2"}, kind="must_not_reach",
        subject_snapshot="s2",
    )
    assert (ok, failed) == (True, None)


def test_no_natural_language_truth_grading():
    store, evidence_id = _store_with_check()
    finding = _finding(
        evidence_ids=[evidence_id],
        statement="everything is fine, trust me, the network sings",
    )
    ok, _ = validate_finding(
        finding,
        store,
        allowed_snapshots={"proposed"},
        kind="must_reach",
        subject_snapshot="proposed",
    )
    assert ok is True
