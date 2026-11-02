"""Backend tool integration tests: live Batfish plus fake-client health cases.

Live tests skip with a reason when Batfish is down. Fake-client tests run
always; they pin the NOT_OK health rules no live fixture can produce.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from netops_lens.batfish_client import HealthRecords
from netops_lens.config import load_settings
from netops_lens.evidence import EvidenceStore
from netops_lens.models import FlowSpec, SnapshotRef
from netops_lens.tools import (
    check_intent,
    compare_snapshots,
    get_acl_rules,
    get_routes,
    get_snapshot_health,
    trace_flow,
)
from tests._fakes import FakeClient, multi_differential_row, raw_differential_row

REPO_ROOT = Path(__file__).resolve().parent.parent
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


def _tcp_flow(port: int, flow_id: str = "f-tcp") -> FlowSpec:
    return _flow(flow_id=flow_id, protocol="TCP", dst_port=port)


@pytest.fixture(scope="module")
def live(batfish_session) -> dict:
    """Connected client with every manifest snapshot initialized."""
    del batfish_session
    settings = load_settings()
    from netops_lens.batfish_client import BatfishClient

    client = BatfishClient(settings.batfish_host, settings.batfish_network)
    client.connect()
    paths = [
        "lab/baseline",
        "lab/proposed",
        "lab/scenarios/healthy/proposed",
        "lab/scenarios/acl_blocks_db/baseline",
        "lab/scenarios/acl_blocks_db/proposed",
    ]
    names = {}
    for path in paths:
        names[path] = client.init_snapshot(REPO_ROOT / path, path.strip("/").replace("/", "-"))
    return {"client": client, "snapshots": names}


def _ref(live, path: str) -> SnapshotRef:
    return SnapshotRef(name=live["snapshots"][path], path=path)


def test_health_ok_on_live_baseline(live):
    store = EvidenceStore()
    result, health = get_snapshot_health(live["client"], store, _ref(live, "lab/baseline"))
    assert result.status == "ok"
    assert health.status == "OK"
    assert health.reasons == ()
    assert len(store) == 1


def test_health_not_ok_on_missing_snapshot(live):
    store = EvidenceStore()
    result, health = get_snapshot_health(
        live["client"], store, SnapshotRef(name="no-such-snapshot", path="lab/baseline")
    )
    assert health.status == "NOT_OK"
    assert health.reasons
    assert result.status == "error"


def test_health_not_ok_on_failed_parse():
    failing = HealthRecords(
        parse_status=({"File_Name": "configs/r1.cfg", "Status": "FAILED"},),
        init_issues=(),
        nodes=({"Node": "r1"},),
    )
    result, health = get_snapshot_health(
        FakeClient(health=failing), EvidenceStore(), SnapshotRef(name="s", path="p")
    )
    assert health.status == "NOT_OK"
    assert result.status == "ok"
    assert any("FAILED" in reason for reason in health.reasons)


def test_health_not_ok_on_any_init_issue():
    failing = HealthRecords(
        parse_status=({"File_Name": "configs/r1.cfg", "Status": "PASSED"},),
        init_issues=(
            {
                "Type": "UNRECOGNIZED",
                "Details": "synthetic warning",
                "Source_Lines": "r1.cfg:1",
                "Line_Text": "mystery",
                "Nodes": "r1",
                "Parser_Context": "ctx",
            },
        ),
        nodes=({"Node": "r1"}, {"Node": "r2"}),
    )
    result, health = get_snapshot_health(
        FakeClient(health=failing), EvidenceStore(), SnapshotRef(name="s", path="p")
    )
    assert health.status == "NOT_OK"
    assert any("synthetic warning" in reason for reason in health.reasons)
    assert result.details["init_issues"][0]["Type"] == "UNRECOGNIZED"


def test_health_not_ok_on_missing_node():
    failing = HealthRecords(
        parse_status=({"File_Name": "configs/r1.cfg", "Status": "PASSED"},),
        init_issues=(),
        nodes=({"Node": "r1"},),
    )
    _, health = get_snapshot_health(
        FakeClient(health=failing), EvidenceStore(), SnapshotRef(name="s", path="p")
    )
    assert health.status == "NOT_OK"
    assert any("r2" in reason for reason in health.reasons)


def test_check_intent_live_matrix(live):
    client = live["client"]
    cases = [
        ("lab/baseline", _flow(flow_id="icmp"), "REACHABLE", "ACCEPTED"),
        ("lab/proposed", _flow(flow_id="icmp"), "UNREACHABLE", "NO_ROUTE"),
        (
            "lab/scenarios/healthy/proposed",
            _flow(flow_id="icmp"),
            "REACHABLE",
            "ACCEPTED",
        ),
        (
            "lab/scenarios/acl_blocks_db/baseline",
            _tcp_flow(1433, "auth"),
            "REACHABLE",
            "ACCEPTED",
        ),
        (
            "lab/scenarios/acl_blocks_db/baseline",
            _tcp_flow(22, "unauth"),
            "UNREACHABLE",
            "DENIED_IN",
        ),
        (
            "lab/scenarios/acl_blocks_db/proposed",
            _tcp_flow(1433, "auth"),
            "UNREACHABLE",
            "DENIED_IN",
        ),
    ]
    for path, flow, reachability, disposition in cases:
        store = EvidenceStore()
        result, outcome = check_intent(client, store, flow, _ref(live, path))
        assert result.status == "ok", (path, result.summary)
        assert outcome.reachability == reachability, (path, flow.flow_id)
        assert outcome.batfish_disposition == disposition
        assert result.evidence_id == "ev-0001"


def test_compare_snapshots_live(live):
    client = live["client"]
    flow = _flow(flow_id="icmp")
    store = EvidenceStore()
    result, outcome = compare_snapshots(
        client,
        store,
        flow,
        _ref(live, "lab/baseline"),
        _ref(live, "lab/proposed"),
    )
    assert result.status == "ok"
    assert outcome.reported_changed is True
    assert outcome.conclusive is True
    assert outcome.snapshot_reach == "UNREACHABLE"
    assert outcome.reference_reach == "REACHABLE"
    assert outcome.snapshot_trace_total >= 1
    assert outcome.reference_trace_total >= 1

    healthy = _flow(flow_id="icmp")
    store2 = EvidenceStore()
    result2, outcome2 = compare_snapshots(
        client,
        store2,
        healthy,
        _ref(live, "lab/baseline"),
        _ref(live, "lab/scenarios/healthy/proposed"),
    )
    assert result2.status == "ok"
    assert outcome2.reported_changed is False
    assert "not reported changed" in result2.summary


def test_trace_flow_live_denied_reconciles_sequence(live):
    client = live["client"]
    store = EvidenceStore()
    result = trace_flow(
        client,
        store,
        _tcp_flow(1433, "auth"),
        _ref(live, "lab/scenarios/acl_blocks_db/proposed"),
    )
    assert result.status == "ok"
    assert result.details["final_disposition"] == "DENIED_IN"
    matches = result.details["acl_matches"]
    assert len(matches) == 1
    match = matches[0]
    assert match["filter"] == "DB-FILTER"
    assert match["action"] == "DENY"
    assert "1433" in match["matched_line_content"]
    assert match["batfish_line_index"] is None
    assert match["sequence_number"] == 10
    assert match["sequence_source"] == "config-parser"


def test_trace_flow_live_accepted_has_no_acl_matches(live):
    client = live["client"]
    result = trace_flow(client, EvidenceStore(), _flow(flow_id="icmp"), _ref(live, "lab/baseline"))
    assert result.status == "ok"
    assert result.details["final_disposition"] == "ACCEPTED"
    assert result.details["acl_matches"] == []


def test_get_routes_live(live):
    client = live["client"]
    result = get_routes(client, EvidenceStore(), _ref(live, "lab/baseline"), node="r1")
    assert result.status == "ok"
    assert result.details["route_count"] >= 1
    assert any(
        row.get("Network") == "198.51.100.0/24"
        and row.get("Protocol") == "static"
        and row.get("Next_Hop") == {"ip": "10.0.12.2", "type": "ip"}
        for row in result.details["routes"]
    )
    missing = get_routes(client, EvidenceStore(), _ref(live, "lab/baseline"), node="r9")
    assert missing.status == "error"
    assert "r9" in missing.summary


def test_get_routes_invalid_prefix():
    result = get_routes(
        FakeClient(),
        EvidenceStore(),
        SnapshotRef(name="s", path="p"),
        node="r1",
        prefix="not-a-prefix",
    )
    assert result.status == "error"


def test_get_acl_rules_live_both_fixtures(live):
    store = EvidenceStore()
    base = get_acl_rules(
        store,
        _ref(live, "lab/scenarios/acl_blocks_db/baseline"),
        node="r1",
        acl="DB-FILTER",
    )
    assert base.status == "ok"
    assert [(r["sequence_number"], r["action"]) for r in base.details["rules"]] == [
        (10, "permit"),
        (20, "deny"),
    ]
    assert base.details["rules"][0]["dst_port"] == 1433
    assert base.details["rules"][1]["dst_port"] == 22
    assert "raw_line" in base.details["rules"][0]

    prop = get_acl_rules(
        store,
        _ref(live, "lab/scenarios/acl_blocks_db/proposed"),
        node="r1",
        acl="DB-FILTER",
    )
    assert prop.details["rules"][0]["action"] == "deny"
    assert prop.details["rules"][0]["sequence_number"] == 10


def test_get_acl_rules_malformed_config(tmp_path):
    snapshot = tmp_path / "configs"
    snapshot.mkdir()
    (snapshot / "r1.cfg").write_text(
        "hostname r1\n"
        "ip access-list extended DB-FILTER\n"
        " 10 permit tcp any any eq 1433\n"
        " permit tcp any any eq 22\n"
    )
    result = get_acl_rules(
        EvidenceStore(),
        SnapshotRef(name="s", path=str(tmp_path)),
        node="r1",
        acl="DB-FILTER",
    )
    assert result.status == "error"
    assert "permit tcp any any eq 22" in result.summary


def test_get_acl_rules_missing_acl(live):
    result = get_acl_rules(
        EvidenceStore(),
        _ref(live, "lab/scenarios/acl_blocks_db/baseline"),
        node="r1",
        acl="NOPE",
    )
    assert result.status == "error"


def test_trace_flow_query_error_is_typed():
    client = FakeClient(failures={("traceroute", "s")})
    result = trace_flow(client, EvidenceStore(), _flow(), SnapshotRef(name="s", path="p"))
    assert result.status == "error"


def test_compare_query_error_is_inconclusive():
    client = FakeClient(failures={("differentialReachability", "prop")})
    store = EvidenceStore()
    result, outcome = compare_snapshots(
        client,
        store,
        _flow(),
        SnapshotRef(name="base", path="b"),
        SnapshotRef(name="prop", path="p"),
    )
    assert result.status == "inconclusive"
    assert outcome.query_ok is False


def test_check_intent_empty_answer_is_inconclusive():
    client = FakeClient(answers={("traceroute", "s"): []})
    store = EvidenceStore()
    result, outcome = check_intent(client, store, _flow(), SnapshotRef(name="s", path="p"))
    assert result.status == "inconclusive"
    assert outcome.reachability == "UNKNOWN"


def test_compare_multiple_consistent_traces_corroborates():
    answers = {
        ("differentialReachability", "prop"): [
            multi_differential_row(
                ["NO_ROUTE", "NO_ROUTE"],
                ["ACCEPTED"],
                snapshot_total=3,
                reference_total=2,
            ),
            multi_differential_row(
                ["DENIED_IN"],
                ["ACCEPTED"],
                snapshot_total=3,
                reference_total=2,
            ),
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
    assert result.status == "ok"
    assert outcome.reported_changed is True
    assert outcome.conclusive is True
    assert outcome.snapshot_reach == "UNREACHABLE"
    assert outcome.reference_reach == "REACHABLE"
    assert outcome.snapshot_trace_total == 3
    assert outcome.reference_trace_total == 2
    assert result.details["snapshot_trace_total"] == 3


def test_compare_conflicting_traces_is_inconclusive():
    answers = {
        ("differentialReachability", "prop"): [
            multi_differential_row(["NO_ROUTE", "ACCEPTED"], ["ACCEPTED"])
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
    assert result.status == "inconclusive"
    assert store.get(result.evidence_id).disposition == "AMBIGUOUS"
    assert outcome.reported_changed is True
    assert outcome.query_ok is True
    assert outcome.conclusive is False


def test_compare_unknown_disposition_trace_is_inconclusive():
    answers = {
        ("differentialReachability", "prop"): [
            multi_differential_row(["NO_ROUTE"], ["SOME_FUTURE_DISPOSITION"])
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
    assert result.status == "inconclusive"
    assert outcome.conclusive is False


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


def test_compare_complete_both_sides_evaluates_normally():
    result, outcome, _ = _compare([multi_differential_row(["NO_ROUTE"], ["ACCEPTED"])])
    assert result.status == "ok"
    assert outcome.conclusive is True
    assert outcome.snapshot_reach == "UNREACHABLE"
    assert outcome.reference_reach == "REACHABLE"
    assert outcome.snapshot_reported_total == 1
    assert outcome.reference_reported_total == 1
    assert result.details["snapshot_complete"] is True
    assert result.details["reference_complete"] is True


def test_compare_snapshot_truncated_is_inconclusive():
    result, outcome, _ = _compare(
        [multi_differential_row(["NO_ROUTE"], ["ACCEPTED"], snapshot_total=4)]
    )
    assert result.status == "inconclusive"
    assert outcome.conclusive is False
    assert outcome.query_ok is True
    assert outcome.snapshot_reported_total == 4
    assert "truncation" in result.summary
    assert "returned 1 of reported 4" in result.summary


def test_compare_reference_truncated_is_inconclusive():
    result, outcome, _ = _compare(
        [multi_differential_row(["NO_ROUTE"], ["ACCEPTED"], reference_total=7)]
    )
    assert result.status == "inconclusive"
    assert outcome.conclusive is False
    assert outcome.reference_reported_total == 7


def test_compare_both_sides_truncated_is_inconclusive():
    result, outcome, _ = _compare([multi_differential_row(["NO_ROUTE"], ["ACCEPTED"], 3, 2)])
    assert result.status == "inconclusive"
    assert outcome.conclusive is False
    assert "truncation" in result.summary


def test_compare_missing_count_is_uncertain():
    result, outcome, _ = _compare([raw_differential_row(drop=("Snapshot_TraceCount",))])
    assert result.status == "inconclusive"
    assert outcome.conclusive is False
    assert "uncertain" in result.summary


def test_compare_invalid_counts_are_uncertain():
    for bad in ("twelve", -1, 1.5, True, None):
        result, outcome, _ = _compare([raw_differential_row(Snapshot_TraceCount=bad)])
        assert result.status == "inconclusive", bad
        assert outcome.conclusive is False, bad
        assert "uncertain" in result.summary, bad


def test_compare_different_totals_both_complete_evaluates_normally():
    result, outcome, _ = _compare(
        [multi_differential_row(["NO_ROUTE", "NO_ROUTE"], ["ACCEPTED"] * 3)]
    )
    assert result.status == "ok"
    assert outcome.conclusive is True
    assert outcome.snapshot_reach == "UNREACHABLE"
    assert outcome.reference_reach == "REACHABLE"
    assert outcome.snapshot_trace_total == 2
    assert outcome.reference_trace_total == 3
    assert outcome.snapshot_reported_total == 2
    assert outcome.reference_reported_total == 3


def test_compare_conflicting_complete_traces_stays_inconclusive():
    result, outcome, store = _compare(
        [multi_differential_row(["NO_ROUTE", "ACCEPTED"], ["ACCEPTED"])]
    )
    assert result.status == "inconclusive"
    assert outcome.conclusive is False
    assert store.get(result.evidence_id).disposition == "AMBIGUOUS"
    assert result.details["snapshot_complete"] is True
    assert result.details["reference_complete"] is True


def test_compare_five_unanimous_of_twelve_is_inconclusive():
    """Five unanimous returned traces prove nothing when twelve are reported."""
    result, outcome, store = _compare(
        [
            multi_differential_row(
                ["NO_ROUTE"] * 3,
                ["ACCEPTED"] * 3,
                snapshot_total=12,
                reference_total=12,
            ),
            multi_differential_row(
                ["NO_ROUTE"] * 2,
                ["ACCEPTED"] * 2,
                snapshot_total=12,
                reference_total=12,
            ),
        ]
    )
    assert result.status == "inconclusive"
    assert outcome.conclusive is False
    assert outcome.snapshot_trace_total == 5
    assert outcome.reference_trace_total == 5
    assert outcome.snapshot_reported_total == 12
    assert outcome.reference_reported_total == 12
    assert "returned 5 of reported 12" in result.summary
    assert store.get(result.evidence_id).disposition == "TRUNCATED"


def test_compare_denied_family_row_maps_to_unreachable():
    answers = {
        ("differentialReachability", "prop"): [multi_differential_row(["DENIED_IN"], ["NO_ROUTE"])]
    }
    store = EvidenceStore()
    result, outcome = compare_snapshots(
        FakeClient(answers=answers),
        store,
        _flow(),
        SnapshotRef(name="base", path="b"),
        SnapshotRef(name="prop", path="p"),
    )
    assert result.status == "ok"
    assert outcome.conclusive is True
    assert outcome.snapshot_reach == "UNREACHABLE"
    assert outcome.reference_reach == "UNREACHABLE"


def test_get_routes_valid_node_no_match(live):
    result = get_routes(
        live["client"],
        EvidenceStore(),
        _ref(live, "lab/baseline"),
        node="r1",
        prefix="203.0.113.0/24",
    )
    assert result.status == "ok"
    assert result.details["route_found"] is False
    assert result.details["routes"] == []
    # No-route on a valid router is an ok empty table, not a node error.
    assert "unknown node" not in result.summary


def test_get_routes_empty_on_valid_node_synthetic():
    answers = {
        ("routes", "s"): [],
        ("nodeProperties", "s"): [{"Node": "r1"}, {"Node": "r2"}],
    }
    result = get_routes(
        FakeClient(answers=answers),
        EvidenceStore(),
        SnapshotRef(name="s", path="p"),
        node="r1",
        prefix="203.0.113.0/24",
    )
    assert result.status == "ok"
    assert result.details["route_found"] is False


def test_get_routes_missing_node_is_error(live):
    result = get_routes(live["client"], EvidenceStore(), _ref(live, "lab/baseline"), node="r9")
    assert result.status == "error"
    assert "unknown node" in result.summary


def test_get_routes_query_failure_is_error():
    client = FakeClient(failures={("routes", "s")})
    result = get_routes(client, EvidenceStore(), SnapshotRef(name="s", path="p"), node="r1")
    assert result.status == "error"
