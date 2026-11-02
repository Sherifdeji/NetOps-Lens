"""Evidence store + four-check validation tests (no Batfish, no LLM)."""

from __future__ import annotations

import json

from netops_lens.evidence import EvidenceStore, validate_finding
from netops_lens.models import ClaimType, Finding


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


def test_route_absent_accepts_empty_ok_table():
    store = EvidenceStore()
    evidence_id = store.record(
        tool="get_routes",
        snapshots=["s"],
        details={
            "tool_status": "ok",
            "route_found": False,
            "route_count": 0,
            "routes": [],
        },
    )
    finding = _finding(
        claim_type=ClaimType.ROUTE_ABSENT,
        flow_id=None,
        evidence_ids=[evidence_id],
        statement="no route to 203.0.113.0/24 on r1",
        severity="info",
    )
    ok, failed = validate_finding(finding, store, allowed_snapshots={"s"})
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
