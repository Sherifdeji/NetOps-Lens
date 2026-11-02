"""N-02/N-04 differential row-aggregation tests (synthetic, never live).

Proves the aggregation policy: per-row validation, concrete-instance
grouping, exact-duplicate dedup, no cross-row count merging. Live
Batfish behavior still yields single-row answers (see
docs/phase23-differential-observation.md); multi-row handling below is
defensive and explicitly synthetic.
"""

from __future__ import annotations

from netops_lens.evidence import EvidenceStore
from netops_lens.models import FlowSpec, SnapshotRef
from netops_lens.tools import compare_snapshots
from tests._fakes import FakeClient, flow_dict, multi_differential_row

START = "@enter(r1[GigabitEthernet0/1])"


def _flow(**overrides) -> FlowSpec:
    payload = {
        "flow_id": "f",
        "src_ip": "192.0.2.10",
        "dst_ip": "198.51.100.1",
        "protocol": "ICMP",
        "start_location": START,
    }
    payload.update(overrides)
    return FlowSpec(**payload)


def _compare(rows: list):
    store = EvidenceStore()
    result, outcome = compare_snapshots(
        FakeClient(answers={("differentialReachability", "prop"): rows}),
        store,
        _flow(),
        SnapshotRef(name="base", path="b"),
        SnapshotRef(name="prop", path="p"),
    )
    return result, outcome, store


def test_three_concrete_flows_with_different_complete_counts():
    """Three instances, per-row totals 1, 2 and 3, all agreeing: conclusive."""
    result, outcome, _ = _compare(
        [
            multi_differential_row(["NO_ROUTE"], ["ACCEPTED"]),
            multi_differential_row(
                ["NO_ROUTE", "NO_ROUTE"],
                ["ACCEPTED", "ACCEPTED"],
                flow=flow_dict(sport=50001),
            ),
            multi_differential_row(
                ["DENIED_IN"] * 3,
                ["ACCEPTED"] * 3,
                flow=flow_dict(sport=50002),
            ),
        ]
    )
    assert result.status == "ok", result.details
    assert outcome.conclusive is True
    assert outcome.snapshot_reach == "UNREACHABLE"
    assert outcome.reference_reach == "REACHABLE"
    assert outcome.snapshot_trace_total == 6
    assert outcome.reference_trace_total == 6
    # Different legitimate per-row totals: no single reported value.
    assert outcome.snapshot_reported_total is None
    assert result.details["distinct_instance_count"] == 3


def test_two_flows_differing_only_in_source_port():
    """Ephemeral source ports distinguish instances; agreement corroborates."""
    result, outcome, _ = _compare(
        [
            multi_differential_row(["NO_ROUTE"], ["ACCEPTED"]),
            multi_differential_row(
                ["DENIED_OUT"], ["ACCEPTED"], flow=flow_dict(sport=51999)
            ),
        ]
    )
    assert result.status == "ok", result.details
    assert outcome.conclusive is True
    assert outcome.snapshot_reach == "UNREACHABLE"
    assert outcome.reference_reach == "REACHABLE"
    assert result.details["distinct_instance_count"] == 2


def test_exact_duplicate_row_is_deduplicated():
    """Byte-identical rows collapse to one instance instead of conflicting."""
    row = multi_differential_row(["NO_ROUTE"], ["ACCEPTED"])
    result, outcome, _ = _compare([row, dict(row)])
    assert result.status == "ok", result.details
    assert outcome.conclusive is True
    assert outcome.snapshot_trace_total == 1
    assert outcome.snapshot_reported_total == 1
    assert result.details["matched_row_count"] == 2
    assert result.details["distinct_instance_count"] == 1


def test_same_identity_with_conflicting_row_evidence():
    """One concrete Flow, two complete but different rows: never merged."""
    result, outcome, store = _compare(
        [
            multi_differential_row(["NO_ROUTE"], ["ACCEPTED"]),
            multi_differential_row(["ACCEPTED"], ["ACCEPTED"]),
        ]
    )
    assert result.status == "inconclusive"
    assert outcome.conclusive is False
    assert outcome.reported_changed is True
    assert store.get(result.evidence_id).disposition == "AMBIGUOUS"
    assert "conflicting row evidence" in result.summary
    # Counts are not added across the conflicting rows.
    assert outcome.snapshot_trace_total == 0


def test_same_identity_with_different_counts_is_inconclusive():
    """Same Flow, same dispositions, but different reported counts."""
    result, outcome, _ = _compare(
        [
            multi_differential_row(["NO_ROUTE"], ["ACCEPTED"]),
            multi_differential_row(
                ["NO_ROUTE"], ["ACCEPTED"], snapshot_total=2, reference_total=1
            ),
        ]
    )
    assert result.status == "inconclusive"
    assert outcome.conclusive is False


def test_complete_row_plus_truncated_row_is_inconclusive():
    """One complete and one truncated instance: the gap poisons the outcome."""
    result, outcome, store = _compare(
        [
            multi_differential_row(["NO_ROUTE"], ["ACCEPTED"]),
            multi_differential_row(
                ["DENIED_IN"],
                ["ACCEPTED"],
                snapshot_total=4,
                flow=flow_dict(sport=50003),
            ),
        ]
    )
    assert result.status == "inconclusive"
    assert outcome.conclusive is False
    assert store.get(result.evidence_id).disposition == "TRUNCATED"
    assert "returned 1 of reported 4" in result.summary
    assert result.details["distinct_instance_count"] == 2


def test_complete_matching_rows_plus_unrelated_rows():
    """Out-of-scope rows are recorded but never disturb a conclusive result."""
    result, outcome, _ = _compare(
        [
            multi_differential_row(["NO_ROUTE"], ["ACCEPTED"]),
            multi_differential_row(
                ["ACCEPTED"], ["ACCEPTED"], flow=flow_dict(proto="TCP", dport=80)
            ),
        ]
    )
    assert result.status == "ok", result.details
    assert outcome.conclusive is True
    assert outcome.snapshot_reach == "UNREACHABLE"
    assert len(outcome.out_of_scope) == 1


def test_incomplete_matching_plus_complete_unrelated_is_inconclusive():
    """A complete out-of-scope row can never rescue an incomplete match."""
    result, outcome, _ = _compare(
        [
            multi_differential_row(
                ["NO_ROUTE"], ["ACCEPTED"], snapshot_total=9
            ),
            multi_differential_row(
                ["ACCEPTED"], ["ACCEPTED"], flow=flow_dict(proto="TCP", dport=80)
            ),
        ]
    )
    assert result.status == "inconclusive"
    assert outcome.conclusive is False
    assert len(outcome.out_of_scope) == 1
