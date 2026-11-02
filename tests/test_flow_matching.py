"""F-01/F-02 identity and trace-aggregation proofs (Part K obligations).

Proves, against fakes only:
- unrelated differential/traceroute Flows can never corroborate a finding;
- direct reachability never rests on the first trace alone;
- incomplete or conflicting traces become UNKNOWN/inconclusive.
"""

from __future__ import annotations

from netops_lens.evidence import EvidenceStore
from netops_lens.models import FlowSpec, SnapshotRef
from netops_lens.tools import (
    _match_flow,
    check_intent,
    compare_snapshots,
    trace_flow,
)
from tests._fakes import (
    FakeClient,
    differential_row,
    flow_dict,
    multi_trace_row,
    raw_differential_row,
    trace_row,
)

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


def _tcp_flow(**overrides) -> FlowSpec:
    payload = {
        "flow_id": "f-tcp",
        "src_ip": "192.0.2.10",
        "dst_ip": "198.51.100.10",
        "protocol": "TCP",
        "dst_port": 1433,
        "start_location": START,
    }
    payload.update(overrides)
    return FlowSpec(**payload)


# --- F-01: _match_flow identity -------------------------------------------


def test_match_exact_flow():
    assert _match_flow(_flow(), flow_dict())[0] is True


def test_match_ignores_ephemeral_source_port():
    assert _match_flow(_flow(), flow_dict(sport=12345))[0] is True


def test_match_rejects_wrong_source_ip():
    assert _match_flow(_flow(), flow_dict(src="192.0.2.99"))[0] is False


def test_match_rejects_wrong_destination_ip():
    assert _match_flow(_flow(), flow_dict(dst="198.51.100.99"))[0] is False


def test_match_rejects_wrong_protocol():
    assert _match_flow(_flow(), flow_dict(proto="TCP", dport=80))[0] is False


def test_match_rejects_wrong_destination_port():
    assert _match_flow(_tcp_flow(), flow_dict(proto="TCP", dport=22))[0] is False


def test_match_rejects_wrong_start_location():
    assert _match_flow(_flow(), flow_dict(node="r2", iface="GigabitEthernet0/2"))[0] is False


def test_match_rejects_missing_flow_identity():
    assert _match_flow(_flow(), None)[0] is False


def test_match_rejects_malformed_flow_identity():
    assert _match_flow(_flow(), "not-a-dict")[0] is False  # type: ignore[arg-type]
    assert _match_flow(_flow(), {"srcIp": "192.0.2.10"})[0] is False


# --- F-01: unrelated rows cannot corroborate -------------------------------


def test_unrelated_differential_row_cannot_corroborate():
    answers = {
        ("differentialReachability", "prop"): [
            differential_row("NO_ROUTE", "ACCEPTED", flow=flow_dict(proto="TCP", dport=22))
        ]
    }
    store = EvidenceStore()
    result, outcome = compare_snapshots(
        FakeClient(answers=answers),
        store,
        _flow(),
        SnapshotRef(name="base", path="b"),
        SnapshotRef(name="prop", path="p"),
    )
    assert result.status == "inconclusive", result.details
    assert outcome.conclusive is False
    assert outcome.reported_changed is False
    assert len(outcome.out_of_scope) == 1


def test_out_of_scope_traceroute_rows_are_unknown():
    answers = {
        ("traceroute", "s"): [trace_row("ACCEPTED", flow=flow_dict(proto="TCP", dport=22))]
    }
    store = EvidenceStore()
    result, outcome = check_intent(
        FakeClient(answers=answers), store, _flow(), SnapshotRef(name="s", path="p")
    )
    assert result.status == "inconclusive"
    assert outcome.reachability == "UNKNOWN"


def test_missing_trace_count_is_uncertain():
    row = trace_row("ACCEPTED")
    del row["TraceCount"]
    answers = {("traceroute", "s"): [row]}
    store = EvidenceStore()
    result, outcome = check_intent(
        FakeClient(answers=answers), store, _flow(), SnapshotRef(name="s", path="p")
    )
    assert result.status == "inconclusive"
    assert outcome.reachability == "UNKNOWN"


# --- F-02: every trace counts ----------------------------------------------


def test_multiple_unanimous_accepted_traces_are_reachable():
    answers = {("traceroute", "s"): [multi_trace_row(["ACCEPTED"] * 3)]}
    store = EvidenceStore()
    result, outcome = check_intent(
        FakeClient(answers=answers), store, _flow(), SnapshotRef(name="s", path="p")
    )
    assert result.status == "ok", result.details
    assert outcome.reachability == "REACHABLE"


def test_multiple_unanimous_noroute_traces_are_unreachable():
    answers = {("traceroute", "s"): [multi_trace_row(["NO_ROUTE"] * 2)]}
    store = EvidenceStore()
    result, outcome = check_intent(
        FakeClient(answers=answers), store, _flow(), SnapshotRef(name="s", path="p")
    )
    assert result.status == "ok"
    assert outcome.reachability == "UNREACHABLE"


def test_conflicting_traces_are_unknown():
    answers = {("traceroute", "s"): [multi_trace_row(["ACCEPTED", "NO_ROUTE"])]}
    store = EvidenceStore()
    result, outcome = check_intent(
        FakeClient(answers=answers), store, _flow(), SnapshotRef(name="s", path="p")
    )
    assert result.status == "inconclusive"
    assert outcome.reachability == "UNKNOWN"


def test_truncated_trace_set_is_unknown():
    row = multi_trace_row(["ACCEPTED"] * 2)
    row["TraceCount"] = 5
    answers = {("traceroute", "s"): [row]}
    store = EvidenceStore()
    result, outcome = check_intent(
        FakeClient(answers=answers), store, _flow(), SnapshotRef(name="s", path="p")
    )
    assert result.status == "inconclusive"
    assert outcome.reachability == "UNKNOWN"


def test_unknown_disposition_trace_is_unknown():
    answers = {("traceroute", "s"): [trace_row("WOBBLE")] }
    store = EvidenceStore()
    result, outcome = check_intent(
        FakeClient(answers=answers), store, _flow(), SnapshotRef(name="s", path="p")
    )
    assert result.status == "inconclusive"
    assert outcome.reachability == "UNKNOWN"


def test_multiple_matching_rows_aggregate_conservatively():
    answers = {
        ("traceroute", "s"): [trace_row("ACCEPTED"), trace_row("NO_ROUTE")],
    }
    store = EvidenceStore()
    result, outcome = check_intent(
        FakeClient(answers=answers), store, _flow(), SnapshotRef(name="s", path="p")
    )
    assert result.status == "inconclusive"
    assert outcome.reachability == "UNKNOWN"


def test_empty_traces_with_zero_count_is_unknown():
    answers = {("traceroute", "s"): [{"Flow": flow_dict(), "Traces": [], "TraceCount": 0}]}
    store = EvidenceStore()
    result, outcome = check_intent(
        FakeClient(answers=answers), store, _flow(), SnapshotRef(name="s", path="p")
    )
    assert result.status == "inconclusive"
    assert outcome.reachability == "UNKNOWN"


def test_trace_flow_flags_partial_evidence():
    row = multi_trace_row(["ACCEPTED"] * 2)
    row["TraceCount"] = 4
    answers = {("traceroute", "s"): [row]}
    store = EvidenceStore()
    result = trace_flow(
        FakeClient(answers=answers), store, _flow(), SnapshotRef(name="s", path="p")
    )
    assert result.status == "inconclusive"
    assert result.details["trace_complete"] is False
    assert result.details["final_disposition"] is None


def test_trace_flow_complete_unanimous_is_ok():
    answers = {("traceroute", "s"): [multi_trace_row(["ACCEPTED"] * 2)]}
    store = EvidenceStore()
    result = trace_flow(
        FakeClient(answers=answers), store, _flow(), SnapshotRef(name="s", path="p")
    )
    assert result.status == "ok", result.details
    assert result.details["trace_complete"] is True
    assert result.details["final_disposition"] == "ACCEPTED"


def test_raw_differential_row_without_identity_is_out_of_scope():
    answers = {("differentialReachability", "prop"): [raw_differential_row(drop=("Flow",))]}
    store = EvidenceStore()
    result, outcome = compare_snapshots(
        FakeClient(answers=answers),
        store,
        _flow(),
        SnapshotRef(name="base", path="b"),
        SnapshotRef(name="prop", path="p"),
    )
    assert result.status == "inconclusive"
    assert outcome.conclusive is False
