"""F-12 evidence-boundary tests: stale records never authorize candidates.

The Stage B entry boundary (``evidence_boundary`` in ``agent._RunContext``)
freezes the evidence IDs that already exist when an invocation starts.
Candidate validation only honors records minted after that boundary: Stage A
output, or evidence minted by an earlier invocation sharing the same store,
can neither support nor veto a submission. All transports here are
scripted; no Muse calls, no Batfish.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

from netops_lens.agent import run_stage_b
from netops_lens.config import Settings
from netops_lens.evidence import EvidenceStore
from netops_lens.models import (
    AssessmentResult,
    ClaimType,
    Finding,
    FlowComparison,
    Intent,
    SnapshotRef,
)
from netops_lens.tools import get_acl_rules, get_routes
from tests._fakes import FakeClient, flow_dict, trace_row

REPO_ROOT = Path(__file__).resolve().parent.parent
START = "@enter(r1[GigabitEthernet0/1])"
BASE = SnapshotRef(name="base", path="b")
PROP = SnapshotRef(name="prop", path="p")
ACL_PROP = SnapshotRef(
    name="prop", path=str(REPO_ROOT / "lab" / "scenarios" / "acl_blocks_db" / "proposed")
)
ROUTE_ROW = {"Network": "198.51.100.0/24", "Protocol": "static", "Next_Hop": {"ip": "10.0.12.2"}}
DENY_1433 = "10 deny tcp 192.0.2.0 0.0.0.255 198.51.100.0 0.0.0.255 eq 1433"

FDB_FLOW = flow_dict(proto="TCP", dport=1433)


def _intent() -> Intent:
    return Intent(
        version=1,
        must_reach=[
            {
                "flow_id": "f-db",
                "src_ip": "192.0.2.10",
                "dst_ip": "198.51.100.1",
                "protocol": "TCP",
                "dst_port": 1433,
                "start_location": START,
            }
        ],
        must_not_reach=[],
    )


def _assessment() -> AssessmentResult:
    return AssessmentResult(
        verdict="REGRESSION_DETECTED",
        flow_comparisons=(
            FlowComparison(
                flow_id="f-db",
                kind="must_reach",
                baseline_reach="REACHABLE",
                proposed_reach="UNREACHABLE",
                classification="REGRESSION",
            ),
        ),
        findings=(
            Finding(
                finding_id="f-0001",
                claim_type=ClaimType.INTENT_VIOLATED,
                flow_id="f-db",
                statement="flow f-db regressed: REACHABLE -> UNREACHABLE",
                evidence_ids=("ev-0001",),
                severity="error",
            ),
        ),
        inconclusive_reasons=(),
        health=(),
    )


class FakeTransport:
    """Scripted model: pops one canned response per model call."""

    def __init__(self, script: list[dict]):
        self.script = list(script)
        self.messages_seen: list[list[dict]] = []

    def __call__(self, messages: list[dict], tools: list[dict]) -> dict:
        self.messages_seen.append(copy.deepcopy(messages))
        if not self.script:
            return {"content": "done", "tool_calls": []}
        return self.script.pop(0)


def _call(name: str, args: dict, call_id: str = "call-1") -> dict:
    return {"id": call_id, "name": name, "arguments": json.dumps(args)}


def _resp(*calls: dict, content: str | None = None) -> dict:
    return {"content": content, "tool_calls": list(calls)}


def _stage_b(script, *, store, client, proposed=PROP):
    """Run one Stage B invocation with a scripted transport."""
    transport = FakeTransport(copy.deepcopy(script))
    result = run_stage_b(
        client,
        store,
        _assessment(),
        _intent(),
        BASE,
        proposed,
        settings=Settings(),
        transport=transport,
    )
    texts = [
        m["content"]
        for seen in transport.messages_seen
        for m in seen
        if m.get("role") == "tool"
    ]
    return result, "\n".join(texts)


def _route_submit(*, op="add_static_route", prefix="198.51.100.0/24") -> dict:
    node_op = {"op": op, "node": "r1", "prefix": prefix, "next_hop": "10.0.12.2"}
    return {
        "rationale": "restore the missing static route evidenced on baseline",
        "operations": [node_op],
        "target_flow_ids": ["f-db"],
    }


def _acl_submit(rule10: dict) -> dict:
    return {
        "rationale": "repair the denied DB port evidenced by get_acl_rules",
        "operations": [
            {
                "op": "remove_acl_line",
                "node": "r1",
                "acl": "DB-FILTER",
                "sequence_number": 10,
                "expected_rule": {
                    k: rule10[k] for k in ("action", "src", "dst", "protocol", "dst_port")
                },
            },
            {
                "op": "acl_permit",
                "node": "r1",
                "acl": "DB-FILTER",
                "sequence_number": 10,
                "src": rule10["src"],
                "dst": rule10["dst"],
                "protocol": rule10["protocol"],
                "dst_port": rule10["dst_port"],
            },
        ],
        "target_flow_ids": ["f-db"],
    }


def _seed_baseline_routes(store: EvidenceStore) -> None:
    client = FakeClient(answers={("routes", "base"): [dict(ROUTE_ROW)]})
    assert get_routes(client, store, BASE, "r1").details["route_found"] is True


def _seed_proposed_routes(store: EvidenceStore) -> None:
    client = FakeClient(answers={("routes", "prop"): [dict(ROUTE_ROW)]})
    assert get_routes(client, store, PROP, "r1").details["route_found"] is True


def _seed_proposed_acl(store: EvidenceStore) -> list[dict]:
    result = get_acl_rules(store, ACL_PROP, "r1", "DB-FILTER")
    assert result.status == "ok", result.details
    return result.details["rules"]


def _seed_trace(store: EvidenceStore, *, flow_id: str = "f-db") -> None:
    store.record(
        tool="trace_flow",
        snapshots=["prop"],
        flow_id=flow_id,
        disposition="DENIED_IN",
        details={
            "tool_status": "ok",
            "final_disposition": "DENIED_IN",
            "reachability": "UNREACHABLE",
            "raw_dispositions": ["DENIED_IN"],
            "traces": [{"disposition": "DENIED_IN", "hops": []}],
            "trace_complete": True,
            "acl_matches": [
                {
                    "node": "r1",
                    "filter": "DB-FILTER",
                    "resolution": "unique-match",
                    "sequence_number": 10,
                }
            ],
        },
    )


def _denied_trace_row() -> dict:
    hops = [{"node": "r1", "steps": [{"action": "DENIED", "detail": {"filter": "DB-FILTER"}}]}]
    return trace_row("DENIED_IN", hops=hops, flow=dict(FDB_FLOW))


def _submit_only(args: dict) -> list[dict]:
    return [_resp(_call("submit_candidate_patch", args)), _resp(content="stopped")]


# --- stale evidence cannot authorize ------------------------------------


def test_stale_route_evidence_cannot_authorize_add():
    store = EvidenceStore()
    _seed_baseline_routes(store)
    stale = set(store.ids())
    assert stale, "the pre-existing record is the point of the test"
    client = FakeClient()
    result, text = _stage_b(_submit_only(_route_submit()), store=store, client=client)
    assert result.candidates == []
    assert "no baseline get_routes evidence" in text


def test_stale_acl_evidence_cannot_authorize_repair():
    store = EvidenceStore()
    rules = _seed_proposed_acl(store)
    _seed_trace(store)
    rule10 = next(r for r in rules if r["sequence_number"] == 10)
    client = FakeClient()
    result, text = _stage_b(
        _submit_only(_acl_submit(rule10)), store=store, client=client, proposed=ACL_PROP
    )
    assert result.candidates == []
    assert "no proposed-snapshot get_acl_rules evidence" in text


# --- fresh in-run evidence authorizes -----------------------------------


def test_fresh_route_evidence_authorizes_add():
    script = [
        _resp(_call("get_routes", {"snapshot": "baseline", "node": "r1"})),
        _resp(_call("submit_candidate_patch", _route_submit())),
        _resp(content="stopped"),
    ]
    client = FakeClient(answers={("routes", "base"): [dict(ROUTE_ROW)]})
    result, _ = _stage_b(script, store=EvidenceStore(), client=client)
    assert len(result.candidates) == 1
    assert result.candidates[0].candidate_id == "c-01"


def test_fresh_remove_route_evidence_authorizes():
    args = _route_submit(op="remove_static_route")
    script = [
        _resp(_call("get_routes", {"snapshot": "proposed", "node": "r1"})),
        _resp(_call("submit_candidate_patch", args)),
        _resp(content="stopped"),
    ]
    client = FakeClient(answers={("routes", "prop"): [dict(ROUTE_ROW)]})
    result, _ = _stage_b(script, store=EvidenceStore(), client=client)
    assert len(result.candidates) == 1
    assert result.candidates[0].operations[0].op == "remove_static_route"


def test_fresh_acl_evidence_authorizes_repair():
    probe = EvidenceStore()
    rule10 = next(r for r in _seed_proposed_acl(probe) if r["sequence_number"] == 10)
    script = [
        _resp(_call("get_acl_rules", {"snapshot": "proposed", "node": "r1", "acl": "DB-FILTER"})),
        _resp(_call("trace_flow", {"flow_id": "f-db", "snapshot": "proposed"})),
        _resp(_call("submit_candidate_patch", _acl_submit(rule10))),
        _resp(content="stopped"),
    ]
    client = FakeClient(
        answers={
            ("traceroute", "prop"): [_denied_trace_row()],
            ("testFilters", "prop"): [{"Action": "DENY", "Line_Content": DENY_1433}],
        }
    )
    result, _ = _stage_b(script, store=EvidenceStore(), client=client, proposed=ACL_PROP)
    assert len(result.candidates) == 1
    assert [op.op for op in result.candidates[0].operations] == [
        "remove_acl_line",
        "acl_permit",
    ]


# --- mixture: stale present, fresh still authorizes ----------------------


def test_mixture_of_stale_and_fresh_accepts_fresh():
    store = EvidenceStore()
    _seed_baseline_routes(store)  # stale: same scope, predates this invocation
    stale = set(store.ids())
    script = [
        _resp(_call("get_routes", {"snapshot": "baseline", "node": "r1"})),
        _resp(_call("submit_candidate_patch", _route_submit())),
        _resp(content="stopped"),
    ]
    client = FakeClient(answers={("routes", "base"): [dict(ROUTE_ROW)]})
    result, _ = _stage_b(script, store=store, client=client)
    assert len(result.candidates) == 1
    fresh_calls = [log for log in result.tool_activity if log.tool == "get_routes"]
    assert len(fresh_calls) == 1
    assert fresh_calls[0].evidence_id not in stale


# --- repeated invocations on one store do not inherit --------------------


def test_repeated_invocations_share_no_authorization():
    store = EvidenceStore()
    script = [
        _resp(_call("get_routes", {"snapshot": "baseline", "node": "r1"})),
        _resp(_call("submit_candidate_patch", _route_submit())),
        _resp(content="first done"),
    ]
    client = FakeClient(answers={("routes", "base"): [dict(ROUTE_ROW)]})
    first, _ = _stage_b(script, store=store, client=client)
    assert len(first.candidates) == 1

    # Second invocation on the same store, no new tool calls: the first
    # invocation's evidence is stale now and must not authorize anything.
    second, text = _stage_b(_submit_only(_route_submit()), store=store, client=client)
    assert second.candidates == []
    assert "no baseline get_routes evidence" in text

    # ...while fresh evidence in the second invocation still authorizes.
    third, _ = _stage_b(script, store=store, client=client)
    assert len(third.candidates) == 1
    assert third.candidates[0].candidate_id == "c-01"
