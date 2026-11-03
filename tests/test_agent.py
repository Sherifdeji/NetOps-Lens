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


ACL_BASE_SNAP = SnapshotRef(
    name="base", path=str(REPO_ROOT / "lab" / "scenarios" / "acl_blocks_db" / "baseline")
)
ACL_PROP_SNAP = SnapshotRef(
    name="prop", path=str(REPO_ROOT / "lab" / "scenarios" / "acl_blocks_db" / "proposed")
)


def _seed_routes(store: EvidenceStore) -> None:
    client = FakeClient(answers={("routes", "base"): [dict(ROUTE_ROW)]})
    result = get_routes(client, store, BASE, "r1")
    assert result.details["route_found"] is True


def _seed_proposed_routes(store: EvidenceStore) -> None:
    client = FakeClient(answers={("routes", "prop"): [dict(ROUTE_ROW)]})
    result = get_routes(client, store, PROP, "r1")
    assert result.details["route_found"] is True


def _seed_ghost_routes(store: EvidenceStore) -> None:
    ghost = SnapshotRef(name="ghost", path="b")
    client = FakeClient(answers={("routes", "ghost"): [dict(ROUTE_ROW)]})
    result = get_routes(client, store, ghost, "r1")
    assert result.details["route_found"] is True


def _seed_acl(store: EvidenceStore) -> list[dict]:
    """Proposed-snapshot ACL inventory (name 'prop' matches the run context)."""
    result = get_acl_rules(store, ACL_PROP_SNAP, "r1", "DB-FILTER")
    assert result.status == "ok", result.details
    return result.details["rules"]


def _seed_baseline_acl(store: EvidenceStore) -> list[dict]:
    result = get_acl_rules(store, ACL_BASE_SNAP, "r1", "DB-FILTER")
    assert result.status == "ok", result.details
    return result.details["rules"]


def _seed_trace(
    store: EvidenceStore,
    *,
    flow_id: str = "f-db",
    snapshot: str = "prop",
    resolution: str = "unique-match",
    node: str = "r1",
    acl: str = "DB-FILTER",
    sequence: int = 10,
) -> None:
    store.record(
        tool="trace_flow",
        snapshots=[snapshot],
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
                    "node": node,
                    "filter": acl,
                    "resolution": resolution,
                    "sequence_number": sequence,
                }
            ],
        },
    )


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
    _seed_trace(store)
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
    _seed_trace(store)
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
    _seed_trace(store)
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
    assert "same-snapshot tool evidence" in _tool_text(transport)
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


def test_budget_enforced_before_each_call_in_a_batch():
    # F-10: with budget 1 and two calls in one response, the second call
    # is neither executed nor logged (no "budget exhausted" pseudo-result).
    one = _call("trace_flow", {"flow_id": "f-db", "snapshot": "baseline"}, call_id="a")
    two = _call("trace_flow", {"flow_id": "f-db", "snapshot": "proposed"}, call_id="b")
    script = [_resp(one, two, content="working")]
    client = FakeClient(
        answers={
            ("traceroute", "base"): [trace_row("ACCEPTED")],
            ("traceroute", "prop"): [trace_row("NO_ROUTE")],
        }
    )
    settings = Settings(agent_max_tool_calls=1)
    result, transport, _ = _run(script, settings=settings, client=client)
    assert len(result.tool_activity) == 1
    assert len(client.calls) == 1  # second call never executed
    assert "budget" not in _tool_text(transport)
    assert result.narrative == "working"


def test_fallback_call_ids_are_unique_within_a_batch():
    # F-10: two provider-id-less calls in one batch get distinct IDs.
    first = {
        "name": "trace_flow",
        "arguments": json.dumps({"flow_id": "f-db", "snapshot": "baseline"}),
    }
    second = {
        "name": "trace_flow",
        "arguments": json.dumps({"flow_id": "f-db", "snapshot": "baseline"}),
    }
    script = [_resp(first, second), _resp(content="done")]
    client = FakeClient(answers={("traceroute", "base"): [trace_row("ACCEPTED")]})
    settings = Settings(agent_max_tool_calls=5)
    result, transport, _ = _run(script, settings=settings, client=client)
    assert len(result.tool_activity) == 2
    tool_messages = [m for m in transport.messages_seen[-1] if m.get("role") == "tool"]
    assert len(tool_messages) == 2
    assert tool_messages[0]["tool_call_id"] != tool_messages[1]["tool_call_id"]
    assert len(client.calls) == 2


def test_unknown_finding_ids_hidden_in_narrative():
    script = [_resp(content="Root cause per [f-0001]; also see [f-9999].")]
    result, _, _ = _run(script)
    assert result.narrative is not None
    assert "[f-0001]" in result.narrative
    assert "f-9999" not in result.narrative
    assert "f-????" in result.narrative


def test_tools_for_verdict_registration():
    # F-05: only REGRESSION_DETECTED registers any tools at all.
    regression = {t["function"]["name"] for t in tools_for_verdict("REGRESSION_DETECTED")}
    assert regression == {"trace_flow", "get_routes", "get_acl_rules", "submit_candidate_patch"}
    assert tools_for_verdict("NO_REGRESSION_DETECTED") == []
    assert tools_for_verdict("INCONCLUSIVE") == []
    assert submit_tool_spec()["function"]["name"] == "submit_candidate_patch"


def test_no_regression_registers_no_tools():
    script = [_resp(content="All checks passed; nothing to fix.")]
    result, transport, _ = _run(script, verdict="NO_REGRESSION_DETECTED")
    assert transport.tools_seen[0] == []
    assert result.candidates == []
    assert result.tool_activity == []
    assert result.narrative == "All checks passed; nothing to fix."


def test_prompt_names_tools_only_for_regression():
    # F-11: the prompt must never claim tools Python did not register.
    from netops_lens import prompts as prompt_module

    regression = prompt_module.build_system_prompt(
        verdict="REGRESSION_DETECTED", allow_candidates=True
    )
    for tool in ("trace_flow", "get_routes", "get_acl_rules", "submit_candidate_patch"):
        assert tool in regression
    assert "proposed snapshot" in regression
    for verdict in ("NO_REGRESSION_DETECTED", "INCONCLUSIVE"):
        text = prompt_module.build_system_prompt(verdict=verdict, allow_candidates=False)
        for tool in ("trace_flow", "get_routes", "get_acl_rules", "submit_candidate_patch"):
            assert tool not in text, (verdict, tool)
        assert "No investigation tools" in text


def test_prompt_inconclusive_names_untrusted_snapshots():
    from netops_lens import prompts as prompt_module

    text = prompt_module.build_system_prompt(verdict="INCONCLUSIVE", allow_candidates=False)
    assert "untrusted" in text


def test_user_context_hides_submission_for_explain_only_verdicts():
    from netops_lens import prompts as prompt_module

    regression = prompt_module.build_user_context(
        _assessment("REGRESSION_DETECTED"), _intent(), question=""
    )
    assert "valid submit_candidate_patch targets" in regression
    for verdict in ("NO_REGRESSION_DETECTED", "INCONCLUSIVE"):
        text = prompt_module.build_user_context(_assessment(verdict), _intent(), question="")
        assert "submit_candidate_patch targets" not in text
        assert "no patch submission" in text


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


def _submit(args: dict) -> list[dict]:
    return [_resp(_call("submit_candidate_patch", args)), _resp(content="stopped")]


# --- F-01: snapshot-scoped evidence ------------------------------------


def test_baseline_only_acl_evidence_cannot_authorize_removal():
    # Baseline evidence lives under snapshots == ["base"]; the
    # proposed-scoped lookup must not see it at all.
    probe = EvidenceStore()
    proposed_rules = _seed_acl(probe)
    rule10 = next(r for r in proposed_rules if r["sequence_number"] == 10)
    only_baseline = EvidenceStore()
    _seed_baseline_acl(only_baseline)
    _seed_trace(only_baseline)
    result, transport, _ = _run(_submit(_acl_submit(rule10)), store=only_baseline)
    assert "no proposed-snapshot get_acl_rules evidence" in _tool_text(transport)
    assert result.candidates == []


def test_acl_evidence_insertion_order_does_not_change_acceptance():
    rules_prop: list[dict] = []
    for order in ("proposed-first", "baseline-first"):
        store = EvidenceStore()
        if order == "proposed-first":
            rules_prop = _seed_acl(store)
            _seed_baseline_acl(store)
        else:
            _seed_baseline_acl(store)
            rules_prop = _seed_acl(store)
        _seed_trace(store)
        rule10 = next(r for r in rules_prop if r["sequence_number"] == 10)
        result, _, _ = _run(_submit(_acl_submit(rule10)), store=store)
        assert result.candidates and result.candidates[0].candidate_id == "c-01", order


def test_baseline_route_evidence_cannot_authorize_removal():
    store = EvidenceStore()
    _seed_routes(store)  # baseline only
    args = {
        "rationale": "remove the route",
        "operations": [
            {
                "op": "remove_static_route",
                "node": "r1",
                "prefix": "198.51.100.0/24",
                "next_hop": "10.0.12.2",
            }
        ],
        "target_flow_ids": ["f-db"],
    }
    result, transport, _ = _run(_submit(args), store=store)
    assert "no proposed get_routes evidence" in _tool_text(transport)
    assert result.candidates == []


def test_proposed_route_evidence_cannot_authorize_addition():
    store = EvidenceStore()
    _seed_proposed_routes(store)  # proposed only
    result, transport, _ = _run(_submit(_route_submit()), store=store)
    assert "no baseline get_routes evidence" in _tool_text(transport)
    assert result.candidates == []


def test_unrelated_run_evidence_cannot_authorize_candidate():
    store = EvidenceStore()
    _seed_ghost_routes(store)  # snapshots == ["ghost"], never this run's
    result, transport, _ = _run(_submit(_route_submit()), store=store)
    assert "no baseline get_routes evidence" in _tool_text(transport)
    assert result.candidates == []


def test_valid_remove_static_route_accepted():
    store = EvidenceStore()
    _seed_proposed_routes(store)
    args = {
        "rationale": "remove the evidenced proposed route",
        "operations": [
            {
                "op": "remove_static_route",
                "node": "r1",
                "prefix": "198.51.100.0/24",
                "next_hop": "10.0.12.2",
            }
        ],
        "target_flow_ids": ["f-db"],
    }
    result, _, _ = _run(_submit(args), store=store)
    assert len(result.candidates) == 1
    assert result.candidates[0].candidate_id == "c-01"


# --- F-03: route-to-flow binding ----------------------------------------


def _seed_extra_prefix(store: EvidenceStore) -> None:
    rows = [
        dict(ROUTE_ROW),
        {"Network": "10.99.0.0/24", "Protocol": "static", "Next_Hop": {"ip": "10.0.12.2"}},
    ]
    client = FakeClient(answers={("routes", "base"): rows})
    result = get_routes(client, store, BASE, "r1")
    assert result.details["route_found"] is True


def test_unrelated_prefix_rejected_despite_matching_hop():
    store = EvidenceStore()
    _seed_extra_prefix(store)
    result, transport, _ = _run(_submit(_route_submit(prefix="10.99.0.0/24")), store=store)
    assert "covers the destination of no target flow" in _tool_text(transport)
    assert result.candidates == []


def test_wrong_next_hop_rejected():
    store = EvidenceStore()
    _seed_routes(store)
    result, transport, _ = _run(_submit(_route_submit(hop="10.0.12.99")), store=store)
    assert "no baseline get_routes evidence" in _tool_text(transport)
    assert result.candidates == []


def test_wrong_node_rejected():
    store = EvidenceStore()
    _seed_routes(store)
    args = _route_submit()
    args["operations"][0]["node"] = "r9"  # type: ignore[index]
    result, transport, _ = _run(_submit(args), store=store)
    assert "no baseline get_routes evidence" in _tool_text(transport)
    assert result.candidates == []


def test_non_static_protocol_row_rejected():
    store = EvidenceStore()
    row = dict(ROUTE_ROW)
    row["Protocol"] = "ospf"
    client = FakeClient(answers={("routes", "base"): [row]})
    result = get_routes(client, store, BASE, "r1")
    assert result.details["route_found"] is True
    result, transport, _ = _run(_submit(_route_submit()), store=store)
    assert "no baseline get_routes evidence" in _tool_text(transport)
    assert result.candidates == []


# --- F-02: V1 ACL repair shape ------------------------------------------


def _repair_args(rule10: dict) -> dict:
    return _acl_submit(rule10)


def test_permit_without_removal_rejected():
    store = EvidenceStore()
    rules = _seed_acl(store)
    _seed_trace(store)
    rule10 = next(r for r in rules if r["sequence_number"] == 10)
    full = _repair_args(rule10)
    permit_only = dict(full)
    permit_only["operations"] = [full["operations"][1]]
    result, transport, _ = _run(_submit(permit_only), store=store)
    assert "exactly one remove_acl_line plus one acl_permit" in _tool_text(transport)
    assert result.candidates == []


def test_permit_at_occupied_sequence_rejected():
    store = EvidenceStore()
    rules = _seed_acl(store)
    _seed_trace(store, sequence=20)
    rule10 = next(r for r in rules if r["sequence_number"] == 10)
    args = _repair_args(rule10)
    args["operations"][1]["sequence_number"] = 20  # type: ignore[index]
    result, transport, _ = _run(_submit(args), store=store)
    assert "must reuse the exact node, ACL, and sequence freed" in _tool_text(transport)
    assert result.candidates == []


def test_permit_for_wrong_flow_rejected():
    # A well-formed repair for TCP/22 matches no must_reach target.
    store = EvidenceStore()
    rules = _seed_acl(store)
    rule20 = next(r for r in rules if r["sequence_number"] == 20)
    _seed_trace(store, sequence=20)
    body = _rule_body(rule20)
    args = {
        "rationale": "repair the wrong port",
        "operations": [
            {
                "op": "remove_acl_line",
                "node": "r1",
                "acl": "DB-FILTER",
                "sequence_number": 20,
                "expected_rule": body,
            },
            {
                "op": "acl_permit",
                "node": "r1",
                "acl": "DB-FILTER",
                "sequence_number": 20,
                "src": rule20["src"],
                "dst": rule20["dst"],
                "protocol": rule20["protocol"],
                "dst_port": rule20["dst_port"],
            },
        ],
        "target_flow_ids": ["f-block"],
    }
    result, transport, _ = _run(_submit(args), store=store)
    assert "must serve a targeted must_reach flow" in _tool_text(transport)
    assert result.candidates == []


def test_mismatched_permit_fields_rejected():
    store = EvidenceStore()
    rules = _seed_acl(store)
    _seed_trace(store)
    rule10 = next(r for r in rules if r["sequence_number"] == 10)
    args = _repair_args(rule10)
    args["operations"][1]["src"] = "any"  # type: ignore[index]
    result, transport, _ = _run(_submit(args), store=store)
    assert "must match the removed rule's source" in _tool_text(transport)
    assert result.candidates == []


def test_mismatched_permit_protocol_rejected():
    store = EvidenceStore()
    rules = _seed_acl(store)
    _seed_trace(store)
    rule10 = next(r for r in rules if r["sequence_number"] == 10)
    args = _repair_args(rule10)
    args["operations"][1]["protocol"] = "udp"  # type: ignore[index]
    result, transport, _ = _run(_submit(args), store=store)
    assert "must match the removed rule's source" in _tool_text(transport)
    assert result.candidates == []


def test_deny_op_outside_repair_shape_rejected():
    store = EvidenceStore()
    rules = _seed_acl(store)
    _seed_trace(store)
    rule10 = next(r for r in rules if r["sequence_number"] == 10)
    args = _repair_args(rule10)
    args["operations"][1]["op"] = "acl_deny"  # type: ignore[index]
    result, transport, _ = _run(_submit(args), store=store)
    assert "exactly one remove_acl_line plus one acl_permit" in _tool_text(transport)
    assert result.candidates == []


def test_extra_operation_outside_repair_shape_rejected():
    store = EvidenceStore()
    rules = _seed_acl(store)
    _seed_trace(store)
    rule10 = next(r for r in rules if r["sequence_number"] == 10)
    args = _repair_args(rule10)
    args["operations"].append(  # type: ignore[attr-defined]
        {
            "op": "add_static_route",
            "node": "r1",
            "prefix": "198.51.100.0/24",
            "next_hop": "10.0.12.2",
        }
    )
    result, transport, _ = _run(_submit(args), store=store)
    assert "no route/ACL mix" in _tool_text(transport)
    assert result.candidates == []


def test_removal_of_nonexistent_rule_rejected():
    store = EvidenceStore()
    rules = _seed_acl(store)
    _seed_trace(store)
    rule10 = next(r for r in rules if r["sequence_number"] == 10)
    args = _acl_submit(rule10, sequence=99)
    result, transport, _ = _run(_submit(args), store=store)
    assert "is not evidenced" in _tool_text(transport)
    assert result.candidates == []


# --- R-2: attribution scoped to the relevant flow ------------------------


def test_unrelated_target_flow_attribution_does_not_veto_valid_repair():
    # R-2: f-db uniquely attributes the seq-10 deny; f-block (also
    # targeted) uniquely attributes a different rule. The f-db repair
    # must still be accepted: unrelated attributions neither support
    # nor veto it.
    store = EvidenceStore()
    rules = _seed_acl(store)
    rule10 = next(r for r in rules if r["sequence_number"] == 10)
    _seed_trace(store)
    _seed_trace(store, flow_id="f-block", sequence=20)
    args = _acl_submit(rule10)
    args["target_flow_ids"] = ["f-db", "f-block"]
    result, _, _ = _run(_submit(args), store=store)
    assert len(result.candidates) == 1
    assert result.candidates[0].candidate_id == "c-01"


# --- F-04: trace attribution --------------------------------------------


def test_acl_repair_rejected_without_trace_attribution():
    store = EvidenceStore()
    rules = _seed_acl(store)
    rule10 = next(r for r in rules if r["sequence_number"] == 10)
    result, transport, _ = _run(_submit(_acl_submit(rule10)), store=store)
    assert "ACL inventory alone is insufficient" in _tool_text(transport)
    assert result.candidates == []


def test_acl_repair_rejected_on_ambiguous_attribution():
    store = EvidenceStore()
    rules = _seed_acl(store)
    _seed_trace(store, resolution="ambiguous")
    rule10 = next(r for r in rules if r["sequence_number"] == 10)
    result, transport, _ = _run(_submit(_acl_submit(rule10)), store=store)
    assert "ambiguous" in _tool_text(transport)
    assert result.candidates == []


def test_acl_repair_rejected_on_wrong_acl_attribution():
    store = EvidenceStore()
    rules = _seed_acl(store)
    _seed_trace(store, acl="OTHER-ACL")
    rule10 = next(r for r in rules if r["sequence_number"] == 10)
    result, transport, _ = _run(_submit(_acl_submit(rule10)), store=store)
    assert "conflicting attribution" in _tool_text(transport)
    assert result.candidates == []


def test_acl_repair_rejected_on_wrong_sequence_attribution():
    store = EvidenceStore()
    rules = _seed_acl(store)
    _seed_trace(store, sequence=20)
    rule10 = next(r for r in rules if r["sequence_number"] == 10)
    result, transport, _ = _run(_submit(_acl_submit(rule10)), store=store)
    assert "conflicting attribution" in _tool_text(transport)
    assert result.candidates == []


def test_acl_repair_ignores_other_flow_trace():
    store = EvidenceStore()
    rules = _seed_acl(store)
    _seed_trace(store, flow_id="f-block")
    rule10 = next(r for r in rules if r["sequence_number"] == 10)
    result, transport, _ = _run(_submit(_acl_submit(rule10)), store=store)
    assert "does not uniquely attribute" in _tool_text(transport)
    assert result.candidates == []
