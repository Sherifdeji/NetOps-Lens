"""Report assembly tests for Stage C (no Batfish, no model calls)."""

from __future__ import annotations

import json

import pytest

from netops_lens.evidence import EvidenceStore
from netops_lens.models import (
    ApplicationResult,
    AssessmentResult,
    CandidatePatch,
    FileDiff,
    FlowComparison,
    InvestigationResult,
    Report,
    ToolResult,
    VerificationResult,
)
from netops_lens.report import ReportError, apply_human_decisions, assemble_report


def _assessment() -> AssessmentResult:
    return AssessmentResult(
        verdict="REGRESSION_DETECTED",
        flow_comparisons=(
            FlowComparison(
                flow_id="web",
                kind="must_reach",
                baseline_reach="REACHABLE",
                proposed_reach="UNREACHABLE",
                classification="REGRESSION",
            ),
        ),
    )


def _candidate() -> CandidatePatch:
    return CandidatePatch(
        candidate_id="c-01",
        rationale="test repair",
        operations=[
            {
                "op": "add_static_route",
                "node": "r1",
                "prefix": "198.51.100.0/24",
                "next_hop": "10.0.12.2",
            }
        ],
        target_flow_ids=["web"],
    )


def _application() -> ApplicationResult:
    return ApplicationResult(
        candidate_id="c-01",
        applied=True,
        changed_files=("configs/r1.cfg",),
        diff=(
            FileDiff(
                file="configs/r1.cfg",
                removed=(),
                added=("ip route 198.51.100.0 255.255.255.0 10.0.12.2",),
            ),
        ),
    )


def _verification(*evidence_ids: str, status: str = "VERIFIED") -> VerificationResult:
    padded = evidence_ids + (evidence_ids[0],) * max(0, 2 - len(evidence_ids))
    evidence_ids = padded
    return VerificationResult(
        candidate_id="c-01",
        status=status,  # type: ignore[arg-type]
        reasons=(),
        checks=(
            {
                "name": "candidate_health",
                "outcome": "pass",
                "detail": "candidate snapshot health OK",
                "evidence_ids": [evidence_ids[0]],
            },
            {
                "name": "intent:web",
                "outcome": "pass",
                "detail": "candidate REACHABLE satisfies must_reach",
                "evidence_ids": [evidence_ids[1]],
            },
        ),
        evidence_ids=tuple(evidence_ids),
        candidate_snapshot="run-candidate-c-01",
    )


def _store_with(*pairs: tuple[str, str]) -> EvidenceStore:
    store = EvidenceStore()
    for tool, flow_id in pairs:
        store.record(tool=tool, snapshots=["run-candidate-c-01"], flow_id=flow_id, details={})
    return store


def test_empty_stage_c_preserves_compatible_report():
    report = assemble_report(
        _assessment(), EvidenceStore(), expected_flow_ids=["web"], investigation=None
    )
    assert report.applications == []
    assert report.verifications == []
    assert report.human_decision == {}
    assert report.evidence_index == {}


def test_populated_stage_c_associates_by_candidate_id():
    store = _store_with(("get_snapshot_health", None), ("check_intent", "web"))
    investigation = InvestigationResult(
        narrative="test", candidates=[_candidate()], tool_activity=[]
    )
    report = assemble_report(
        _assessment(),
        store,
        expected_flow_ids=["web"],
        investigation=investigation,
        applications=[_application()],
        verifications=[_verification("ev-0001", "ev-0002")],
        human_decision={"c-01": "PENDING"},
    )
    assert [a.candidate_id for a in report.applications] == ["c-01"]
    assert [v.candidate_id for v in report.verifications] == ["c-01"]
    assert report.human_decision == {"c-01": "PENDING"}
    assert set(report.evidence_index) >= {"ev-0001", "ev-0002"}
    diff = report.applications[0].diff[0]
    assert diff.file == "configs/r1.cfg"
    assert diff.removed == ()
    assert report.verifications[0].evidence_ids == ("ev-0001", "ev-0002")


def test_duplicate_candidate_records_rejected():
    store = _store_with(("get_snapshot_health", None))
    with pytest.raises(ReportError, match="duplicate"):
        assemble_report(
            _assessment(),
            store,
            expected_flow_ids=["web"],
            applications=[_application(), _application()],
            verifications=[_verification("ev-0001")],
            human_decision={"c-01": "PENDING"},
        )


def test_application_verification_mismatch_rejected():
    store = EvidenceStore()
    other = _verification("ev-0001").model_copy(update={"candidate_id": "c-02"})
    with pytest.raises(ReportError, match="mismatch"):
        assemble_report(
            _assessment(),
            store,
            expected_flow_ids=["web"],
            applications=[_application()],
            verifications=[other],
            human_decision={"c-01": "PENDING", "c-02": "PENDING"},
        )


def test_human_decision_gap_rejected():
    store = EvidenceStore()
    with pytest.raises(ReportError, match="human-decision"):
        assemble_report(
            _assessment(),
            store,
            expected_flow_ids=["web"],
            applications=[_application()],
            verifications=[_verification("ev-0001")],
            human_decision={},
        )


def test_submitted_candidate_without_application_rejected():
    store = EvidenceStore()
    investigation = InvestigationResult(
        narrative="test", candidates=[_candidate()], tool_activity=[]
    )
    with pytest.raises(ReportError, match="without application"):
        assemble_report(
            _assessment(), store, expected_flow_ids=["web"], investigation=investigation
        )


def test_verification_evidence_must_resolve_in_index():
    store = _store_with(("get_snapshot_health", None))
    investigation = InvestigationResult(
        narrative="test", candidates=[_candidate()], tool_activity=[]
    )
    with pytest.raises(ReportError, match="missing evidence"):
        assemble_report(
            _assessment(),
            store,
            expected_flow_ids=["web"],
            investigation=investigation,
            applications=[_application()],
            verifications=[_verification("ev-0001", "ev-9999")],
            human_decision={"c-01": "PENDING"},
        )


def test_stage_c_serializes_without_paths_or_secrets():
    store = _store_with(("get_snapshot_health", None), ("check_intent", "web"))
    investigation = InvestigationResult(
        narrative="test", candidates=[_candidate()], tool_activity=[]
    )
    report = assemble_report(
        _assessment(),
        store,
        expected_flow_ids=["web"],
        investigation=investigation,
        applications=[_application()],
        verifications=[_verification("ev-0001", "ev-0002")],
        human_decision={"c-01": "APPROVED"},
    )
    blob = report.model_dump_json()
    payload = json.loads(blob)
    assert payload["applications"][0]["candidate_id"] == "c-01"
    assert payload["verifications"][0]["candidate_snapshot"] == "run-candidate-c-01"
    assert payload["human_decision"] == {"c-01": "APPROVED"}
    assert "/tmp" not in blob
    assert "META_API_KEY" not in blob
    assert "Authorization" not in blob


def _assembled_report(status: str = "VERIFIED") -> Report:
    """A valid pipeline-shaped report with one VERIFIED/assorted candidate."""
    store = _store_with(("get_snapshot_health", None), ("check_intent", "web"))
    investigation = InvestigationResult(
        narrative="test", candidates=[_candidate()], tool_activity=[]
    )
    return assemble_report(
        _assessment(),
        store,
        expected_flow_ids=["web"],
        investigation=investigation,
        applications=[_application()],
        verifications=[_verification("ev-0001", "ev-0002", status=status)],
        human_decision={"c-01": "PENDING"},
    )


def test_apply_human_decisions_returns_independent_copy():
    # P51-01: mutating nested data in the returned report must not leak
    # into the retained original (Streamlit keeps both alive).
    original = _assembled_report()
    before = original.model_dump_json()
    updated = apply_human_decisions(original, {"c-01": "APPROVED"})
    assert updated.human_decision == {"c-01": "APPROVED"}
    # Exercise actual nested mutable data: lists, the evidence dict, and
    # the nested investigation object.
    updated.applications.append(_application())
    updated.verifications.pop()
    updated.evidence_index.pop("ev-0001")
    assert updated.investigation is not None
    updated.investigation.candidates.clear()
    updated.traces.append(
        ToolResult(
            tool="trace_flow",
            snapshots=["web-baseline"],
            status="ok",
            evidence_id="ev-0001",
        )
    )
    assert original.model_dump_json() == before
    assert len(original.applications) == 1
    assert len(original.verifications) == 1
    assert set(original.evidence_index) >= {"ev-0001", "ev-0002"}
    assert original.investigation is not None
    assert len(original.investigation.candidates) == 1
    assert original.human_decision == {"c-01": "PENDING"}
    assert updated.human_decision == {"c-01": "APPROVED"}
    # Both instances retain valid model structure.
    Report.model_validate(original.model_dump(mode="python"))
    Report.model_validate(updated.model_dump(mode="python"))


@pytest.mark.parametrize("decision", ["PENDING", "REJECTED", "APPROVED"])
def test_apply_human_decisions_missing_verification_raises_report_error(decision):
    # P51-02: an application without a verification entry must raise the
    # project's ReportError, never a bare KeyError, and must leave the
    # original report (and its recorded decision) untouched. The malformed
    # fixture is built with model_copy so production validation is not
    # weakened: assemble_report still refuses this state.
    original = _assembled_report()
    malformed = original.model_copy(update={"verifications": []})
    before = malformed.model_dump_json()
    with pytest.raises(ReportError, match="no verification entry"):
        apply_human_decisions(malformed, {"c-01": decision})
    assert malformed.model_dump_json() == before
    assert malformed.human_decision == {"c-01": "PENDING"}


def test_apply_human_decisions_rejects_unknown_candidate():
    original = _assembled_report()
    before = original.model_dump_json()
    with pytest.raises(ReportError, match="mismatch"):
        apply_human_decisions(original, {"c-09": "PENDING"})
    assert original.model_dump_json() == before


@pytest.mark.parametrize(
    ("status", "decision", "accepted"),
    [
        ("VERIFIED", "APPROVED", True),
        ("VERIFIED", "PENDING", True),
        ("VERIFIED", "REJECTED", True),
        ("REJECTED", "APPROVED", False),
        ("REJECTED", "PENDING", True),
        ("REJECTED", "REJECTED", True),
        ("UNVERIFIABLE", "APPROVED", False),
        ("UNVERIFIABLE", "PENDING", True),
        ("UNVERIFIABLE", "REJECTED", True),
    ],
)
def test_approved_requires_verified_status(status, decision, accepted):
    store = _store_with(("get_snapshot_health", None), ("check_intent", "web"))
    investigation = InvestigationResult(
        narrative="test", candidates=[_candidate()], tool_activity=[]
    )
    kwargs = {
        "expected_flow_ids": ["web"],
        "investigation": investigation,
        "applications": [_application()],
        "verifications": [_verification("ev-0001", "ev-0002", status=status)],
        "human_decision": {"c-01": decision},
    }
    if accepted:
        report = assemble_report(_assessment(), store, **kwargs)
        assert report.human_decision == {"c-01": decision}
    else:
        with pytest.raises(ReportError, match="illegal"):
            assemble_report(_assessment(), store, **kwargs)
