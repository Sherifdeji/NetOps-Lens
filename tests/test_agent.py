"""Stage B deterministic tests: fake transports, real validation (no LLM)."""

from __future__ import annotations

import copy
import json
from pathlib import Path

from netops_lens.agent import (
    AgentError,
    run_stage_b,
    submit_tool_spec,
    tools_for_verdict,
)
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
from tests._fakes import FakeClient, trace_row

REPO_ROOT = Path(__file__).resolve().parent.parent
START = "@enter(r1[GigabitEthernet0/1])"
BASE = SnapshotRef(name="base", path="b")
PROP = SnapshotRef(name="prop", path="p")
ACL_PROP = SnapshotRef(
    name="acl-prop", path=str(REPO_ROOT / "lab" / "scenarios" / "acl_blocks_db" / "proposed")
)
ROUTE_ROW = {"Network": "198.51.100.0/24", "Protocol": "static", "Next_Hop": {"ip": "10.0.12.2"}}


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
        must_not_reach=[
            {
                "flow_id": "f-block",
                "src_ip": "192.0.2.10",
                "dst_ip": "198.51.100.1",
                "protocol": "TCP",
                "dst_port": 22,
                "start_location": START,
            }
        ],
    )


def _assessment(verdict: str = "REGRESSION_DETECTED") -> AssessmentResult:
    return AssessmentResult(
        verdict=verdict,  # type: ignore[arg-type]
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
    """Scripted model: pops responses, deep-copies every inbound message."""

    def __init__(self, script: list[dict]):
        self.script = list(script)
        self.messages_seen: list[list[dict]] = []
        self.tools_seen: list[list[str]] = []
        self.calls = 0

    def __call__(self, messages: list[dict], tools: list[dict]) -> dict:
        self.calls += 1
        self.messages_seen.append(copy.deepcopy(messages))
        self.tools_seen.append([t["function"]["name"] for t in tools])
        if not self.script:
            return {"content": "done", "tool_calls": []}
        return self.script.pop(0)


def _call(name: str, args: dict, call_id: str = "call-1") -> dict:
    return {"id": call_id, "name": name, "arguments": json.dumps(args)}


def _resp(*calls: dict, content: str | None = None) -> dict:
    return {"content": content, "tool_calls": list(calls)}


def _tool_text(transport: FakeTransport, index: int = -1) -> str:
    """Content of the tool-result message(s) delivered after call batch."""
    texts = [
        m["content"] for m in transport.messages_seen[index] if m.get("role") == "tool"
    ]
    return "\n".join(texts)


def _run(
    script: list[dict],
    *,
    verdict: str = "REGRESSION_DETECTED",
    settings: Settings | None = None,
    client: FakeClient | None = None,
    store: EvidenceStore | None = None,
    baseline: SnapshotRef = BASE,
    proposed: SnapshotRef = PROP,
) -> tuple:
    transport = FakeTransport(script)
    store = store if store is not None else EvidenceStore()
    before = _assessment(verdict).model_dump_json()
    assessment = _assessment(verdict)
    result = run_stage_b(
        client if client is not None else FakeClient(),
        store,
        assessment,
        _intent(),
        baseline,
        proposed,
        settings=settings or Settings(),
        transport=transport,
    )
    assert assessment.model_dump_json() == before, "Stage B mutated the assessment"
    return result, transport, store


def test_valid_read_only_investigation():
    client = FakeClient(answers={("traceroute", "base"): [trace_row("ACCEPTED")]})
    script = [
        _resp(_call("trace_flow", {"flow_id": "f-db", "snapshot": "baseline"})),
        _resp(content="Regression explained [f-0001]."),
    ]
    result, transport, store = _run(script, client=client)
    assert result.narrative == "Regression explained [f-0001]."
    assert len(result.tool_activity) == 1
    entry = result.tool_activity[0]
    assert entry.tool == "trace_flow"
    assert entry.evidence_id is not None
    assert store.get(entry.evidence_id) is not None
    assert result.candidates == []


def test_trace_flow_execution_records_evidence():
    client = FakeClient(answers={("traceroute", "prop"): [trace_row("NO_ROUTE")]})
    result, _, store = _run(
        [_resp(_call("trace_flow", {"flow_id": "f-db", "snapshot": "proposed"})),
         _resp(content="traced")],
        client=client,
    )
    record = store.get(result.tool_activity[0].evidence_id or "")
    assert record is not None
    assert record.tool == "trace_flow"
    assert record.snapshots == ["prop"]


def test_get_routes_execution_records_evidence():
    client = FakeClient(answers={("routes", "prop"): [dict(ROUTE_ROW)]})
    result, _, store = _run(
        [_resp(_call("get_routes", {"snapshot": "proposed", "node": "r1"})),
         _resp(content="routed")],
        client=client,
    )
    record = store.get(result.tool_activity[0].evidence_id or "")
    assert record is not None
    assert record.details["node"] == "r1"
    assert record.details["route_found"] is True


def test_get_acl_rules_execution_records_evidence():
    result, _, store = _run(
        [_resp(_call("get_acl_rules", {"snapshot": "baseline", "node": "r1", "acl": "DB-FILTER"})),
         _resp(content="acls")],
        baseline=ACL_PROP,
    )
    record = store.get(result.tool_activity[0].evidence_id or "")
    assert record is not None
    assert record.tool == "get_acl_rules"
    rules = record.details["rules"]
    assert [r["sequence_number"] for r in rules] == [10, 20]


def _seed_routes(store: EvidenceStore) -> None:
    client = FakeClient(answers={("routes", "base"): [dict(ROUTE_ROW)]})
    result = get_routes(client, store, BASE, "r1")
    assert result.details["route_found"] is True


def _seed_acl(store: EvidenceStore) -> list[dict]:
    result = get_acl_rules(store, ACL_PROP, "r1", "DB-FILTER")
    assert result.status == "ok", result.details
    return result.details["rules"]


def _rule_body(rule: dict) -> dict:
    return {k: rule[k] for k in ("action", "src", "dst", "protocol", "dst_port")}


def _route_submit(prefix: str = "198.51.100.0/24", hop: str = "10.0.12.2") -> dict:
    return {
        "rationale": "restore the missing static route evidenced on baseline",
        "operations": [
            {"op": "add_static_route", "node": "r1", "prefix": prefix, "next_hop": hop}
        ],
        "target_flow_ids": ["f-db"],
    }


def test_valid_candidate_submission():
    script = [
        _resp(_call("get_routes", {"snapshot": "baseline", "node": "r1"})),
        _resp(_call("submit_candidate_patch", _route_submit(), call_id="call-2")),
        _resp(content="Route restored as c-01 [f-0001]."),
    ]
    client = FakeClient(answers={("routes", "base"): [dict(ROUTE_ROW)]})
    result, transport, _ = _run(script, client=client)
    assert result.candidates and result.candidates[0].candidate_id == "c-01"
    assert result.candidates[0].operations[0].op == "add_static_route"
    assert result.tool_activity[1].evidence_id is None
    assert result.narrative == "Route restored as c-01 [f-0001]."


def test_invalid_tool_arguments_return_errors():
    script = [
        _resp(_call("trace_flow", {"flow_id": "f-db", "snapshot": "sideways"})),
        _resp(content="noted"),
    ]
    result, transport, store = _run(script)
    assert "invalid" in _tool_text(transport).lower()
    assert result.tool_activity[0].evidence_id is None
    assert len(store.ids()) == 0
    assert result.narrative == "noted"


def test_unknown_flow_id_rejected():
    script = [
        _resp(_call("trace_flow", {"flow_id": "ghost", "snapshot": "baseline"})),
        _resp(content="noted"),
    ]
    result, transport, _ = _run(script)
    assert "unknown flow_id" in _tool_text(transport)
    assert result.candidates == []


def test_unknown_tool_names_rejected():
    script = [
        _resp(_call("delete_routes", {"snapshot": "baseline"})),
        _resp(content="noted"),
    ]
    result, transport, _ = _run(script)
    assert "unknown tool" in _tool_text(transport)
    assert result.candidates == []


def test_free_text_patch_rejected_then_abandoned():
    script = [
        _resp(
            _call(
                "submit_candidate_patch",
                {"rationale": "trust me", "operations": "add permit tcp any any"},
                call_id="call-1",
            )
        ),
        _resp(content="Could not submit; stopping."),
    ]
    result, transport, _ = _run(script)
    assert "schema" in _tool_text(transport)
    assert result.candidates == []
    assert result.narrative == "Could not submit; stopping."


def _acl_submit(rule10: dict, *, sequence: int = 10, expected: dict | None = None) -> dict:
    body = _rule_body(rule10) if expected is None else expected
    rule = dict(rule10)
    return {
        "rationale": "repair the denied DB port evidenced by get_acl_rules",
        "operations": [
            {
                "op": "remove_acl_line",
                "node": "r1",
                "acl": "DB-FILTER",
                "sequence_number": sequence,
                "expected_rule": body,
            },
            {
                "op": "acl_permit",
                "node": "r1",
                "acl": "DB-FILTER",
                "sequence_number": sequence,
                "src": rule["src"],
                "dst": rule["dst"],
                "protocol": rule["protocol"],
                "dst_port": rule["dst_port"],
            },
        ],
        "target_flow_ids": ["f-db"],
    }


def test_guessed_acl_sequence_rejected():
    store = EvidenceStore()
    rules = _seed_acl(store)
    rule10 = next(r for r in rules if r["sequence_number"] == 10)
    script = [
        _resp(_call("submit_candidate_patch", _acl_submit(rule10, sequence=99), call_id="call-1")),
        _resp(content="stopped"),
    ]
    result, transport, _ = _run(script, store=store)
    assert "never guess sequences" in _tool_text(transport)
    assert result.candidates == []


def test_unmatched_expected_rule_rejected():
    store = EvidenceStore()
    rules = _seed_acl(store)
    rule10 = next(r for r in rules if r["sequence_number"] == 10)
    wrong = dict(_rule_body(rule10))
    wrong["action"] = "permit"
    script = [
        _resp(_call("submit_candidate_patch", _acl_submit(rule10, expected=wrong))),
        _resp(content="stopped"),
    ]
    result, transport, _ = _run(script, store=store)
    assert "expected_rule does not match" in _tool_text(transport)
    assert result.candidates == []


def test_valid_acl_repair_accepted():
    store = EvidenceStore()
    rules = _seed_acl(store)
    rule10 = next(r for r in rules if r["sequence_number"] == 10)
    script = [
        _resp(_call("submit_candidate_patch", _acl_submit(rule10))),
        _resp(content="ACL repaired as c-01."),
    ]
    result, _, _ = _run(script, store=store)
    assert len(result.candidates) == 1
    candidate = result.candidates[0]
    assert candidate.candidate_id == "c-01"
    assert [op.op for op in candidate.operations] == ["remove_acl_line", "acl_permit"]
    assert candidate.operations[0].sequence_number == 10  # type: ignore[union-attr]


def test_submission_outside_target_intent_rejected():
    store = EvidenceStore()
    _seed_routes(store)
    args = _route_submit()
    args["target_flow_ids"] = ["nope"]
    script = [_resp(_call("submit_candidate_patch", args)), _resp(content="stopped")]
    result, transport, _ = _run(script, store=store)
    assert "unknown target_flow_ids" in _tool_text(transport)
    assert result.candidates == []


def test_duplicate_target_flow_ids_rejected():
    store = EvidenceStore()
    _seed_routes(store)
    args = _route_submit()
    args["target_flow_ids"] = ["f-db", "f-db"]
    script = [_resp(_call("submit_candidate_patch", args)), _resp(content="stopped")]
    result, transport, _ = _run(script, store=store)
    assert "duplicates" in _tool_text(transport)
    assert result.candidates == []


def test_unguessed_route_rejected_without_evidence():
    script = [
        _resp(_call("submit_candidate_patch", _route_submit(prefix="10.9.9.0/24"))),
        _resp(content="stopped"),
    ]
    result, transport, _ = _run(script)
    assert "need tool evidence" in _tool_text(transport)
    assert result.candidates == []


def test_retry_then_accept():
    store = EvidenceStore()
    _seed_routes(store)
    script = [
        _resp(_call("submit_candidate_patch", _route_submit(prefix="10.9.9.0/24"))),
        _resp(_call("submit_candidate_patch", _route_submit(), call_id="call-2")),
        _resp(content="fixed on retry"),
    ]
    result, _, _ = _run(script, store=store)
    assert len(result.candidates) == 1
    assert result.candidates[0].candidate_id == "c-01"
    assert result.narrative == "fixed on retry"


def test_max_candidates_enforced():
    store = EvidenceStore()
    _seed_routes(store)
    script = [
        _resp(_call("submit_candidate_patch", _route_submit(), call_id="call-1")),
        _resp(_call("submit_candidate_patch", _route_submit(), call_id="call-2")),
        _resp(content="done"),
    ]
    settings = Settings(max_candidates=1)
    result, transport, _ = _run(script, store=store, settings=settings)
    assert len(result.candidates) == 1
    assert "candidate budget exhausted" in _tool_text(transport)


def test_max_patch_retries_enforced():
    store = EvidenceStore()
    bad = _route_submit(prefix="10.9.9.0/24")
    script = [
        _resp(_call("submit_candidate_patch", bad, call_id="call-1")),
        _resp(_call("submit_candidate_patch", bad, call_id="call-2")),
        _resp(content="done"),
    ]
    settings = Settings(max_patch_retries=0)
    result, transport, _ = _run(script, store=store, settings=settings)
    assert result.candidates == []
    assert "retry budget exhausted" in _tool_text(transport)


def test_agent_max_tool_calls_enforced():
    script = [
        _resp(_call("trace_flow", {"flow_id": "f-db", "snapshot": "baseline"}, call_id=f"c{i}"))
        for i in range(10)
    ]
    settings = Settings(agent_max_tool_calls=2)
    result, transport, _ = _run(script, settings=settings)
    assert len(result.tool_activity) == 2
    assert transport.calls == 2
    assert "exhausted" in (result.narrative or "")


def test_unknown_finding_ids_hidden_in_narrative():
    script = [_resp(content="Root cause per [f-0001]; also see [f-9999].")]
    result, _, _ = _run(script)
    assert result.narrative is not None
    assert "[f-0001]" in result.narrative
    assert "f-9999" not in result.narrative
    assert "f-????" in result.narrative


def test_tools_for_verdict_registration():
    regression = {t["function"]["name"] for t in tools_for_verdict("REGRESSION_DETECTED")}
    assert regression == {"trace_flow", "get_routes", "get_acl_rules", "submit_candidate_patch"}
    clean = {t["function"]["name"] for t in tools_for_verdict("NO_REGRESSION_DETECTED")}
    assert clean == {"trace_flow", "get_routes", "get_acl_rules"}
    assert tools_for_verdict("INCONCLUSIVE") == []
    assert submit_tool_spec()["function"]["name"] == "submit_candidate_patch"


def test_no_regression_registers_no_submission_tool():
    script = [_resp(content="All checks passed; nothing to fix.")]
    result, transport, _ = _run(script, verdict="NO_REGRESSION_DETECTED")
    assert "submit_candidate_patch" not in transport.tools_seen[0]
    assert set(transport.tools_seen[0]) == {"trace_flow", "get_routes", "get_acl_rules"}
    assert result.candidates == []
    assert result.tool_activity == []
    assert result.narrative == "All checks passed; nothing to fix."


def test_inconclusive_registers_no_tools():
    script = [_resp(content="Cannot conclude; snapshot health failed.")]
    result, transport, _ = _run(script, verdict="INCONCLUSIVE")
    assert transport.tools_seen[0] == []
    assert result.candidates == []
    assert result.narrative == "Cannot conclude; snapshot health failed."


def test_submit_on_inconclusive_rejected_as_not_allowed():
    script = [
        _resp(_call("submit_candidate_patch", _route_submit())),
        _resp(content="understood"),
    ]
    result, transport, _ = _run(script, verdict="INCONCLUSIVE")
    assert "candidates_not_allowed" in _tool_text(transport)
    assert result.candidates == []


def test_submit_on_no_regression_rejected_as_not_allowed():
    script = [
        _resp(_call("submit_candidate_patch", _route_submit())),
        _resp(content="understood"),
    ]
    result, transport, _ = _run(script, verdict="NO_REGRESSION_DETECTED")
    assert "candidates_not_allowed" in _tool_text(transport)
    assert result.candidates == []


def test_agent_failure_preserves_stage_a():
    before = _assessment().model_dump_json()

    def boom(messages: list[dict], tools: list[dict]) -> dict:
        raise AgentError("transport_error: boom")

    store = EvidenceStore()
    assessment = _assessment()
    result = run_stage_b(
        FakeClient(), store, assessment, _intent(), BASE, PROP,
        settings=Settings(), transport=boom,
    )
    assert result.narrative == "Stage B failed: transport_error: boom"
    assert result.candidates == []
    assert result.tool_activity == []
    assert assessment.model_dump_json() == before


def test_assessment_hash_unchanged_across_stage_b():
    script = [
        _resp(_call("get_routes", {"snapshot": "baseline", "node": "r1"})),
        _resp(content="summary"),
    ]
    client = FakeClient(answers={("routes", "base"): [dict(ROUTE_ROW)]})
    result, _, _ = _run(script, client=client)
    assert result.narrative == "summary"
    assert len(result.tool_activity) == 1
    # Immutability itself is proven by tests/test_immutability.py; the
    # _run helper already asserts hash equality around every Stage B run.
