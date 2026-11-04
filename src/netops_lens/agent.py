"""Stage B: Muse Spark investigation and candidate generation.

Python owns everything factual: the verdict, the findings, tool
registration, argument validation, tool execution, evidence minting, and
candidate acceptance. The model supplies narrative text plus tool-call
requests; every request is validated and executed by Python, and every
candidate is validated against this run's evidence before Python assigns
it an ID. ``agent.py`` never imports Pybatfish and never touches
assessment writers: ``AssessmentResult`` crosses Stage B read-only.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from ipaddress import IPv4Address, IPv4Network
from typing import Callable

import httpx
from pydantic import TypeAdapter, ValidationError

from netops_lens import prompts
from netops_lens.config import Settings, auth_headers, chat_completions_url, load_settings
from netops_lens.evidence import EvidenceStore
from netops_lens.models import (
    AclAction,
    AclPermit,
    AclRule,
    AddStaticRoute,
    AssessmentResult,
    CandidatePatch,
    CandidateSubmission,
    FlowSpec,
    Intent,
    InvestigationResult,
    JsonValue,
    NetOpsModel,
    RemoveAclLine,
    RemoveStaticRoute,
    SnapshotRef,
    ToolCallLog,
)
from netops_lens.tools import get_acl_rules, get_routes, trace_flow

TIMEOUT_S = 60.0


class AgentError(Exception):
    """Stage B setup/transport failure (never a verdict)."""


class SnapshotRole(str, Enum):
    BASELINE = "baseline"
    PROPOSED = "proposed"


class TraceFlowArgs(NetOpsModel):
    flow_id: str
    snapshot: SnapshotRole


class GetRoutesArgs(NetOpsModel):
    snapshot: SnapshotRole
    node: str
    prefix: str | None = None


class GetAclRulesArgs(NetOpsModel):
    snapshot: SnapshotRole
    node: str
    acl: str


def _tool_spec(name: str, description: str, schema: dict) -> dict:
    return {
        "type": "function",
        "function": {"name": name, "description": description, "parameters": schema},
    }


def investigation_tool_specs() -> list[dict]:
    """Read-only tool schemas (verdict-gated by the caller)."""
    role: dict = {"type": "string", "enum": ["baseline", "proposed"]}
    return [
        _tool_spec(
            "trace_flow",
            "Ordered hops and dispositions for one declared flow on one assessed "
            "snapshot. Flow and snapshot are resolved by Python.",
            {
                "type": "object",
                "properties": {"flow_id": {"type": "string"}, "snapshot": role},
                "required": ["flow_id", "snapshot"],
                "additionalProperties": False,
            },
        ),
        _tool_spec(
            "get_routes",
            "Structured route table for one node on one assessed snapshot. "
            "Optional prefix filters to one destination network.",
            {
                "type": "object",
                "properties": {
                    "snapshot": role,
                    "node": {"type": "string"},
                    "prefix": {"type": "string"},
                },
                "required": ["snapshot", "node"],
                "additionalProperties": False,
            },
        ),
        _tool_spec(
            "get_acl_rules",
            "Ordered rules of one Cisco IOS extended ACL parsed from the "
            "snapshot configuration (sequence numbers from the config).",
            {
                "type": "object",
                "properties": {
                    "snapshot": role,
                    "node": {"type": "string"},
                    "acl": {"type": "string"},
                },
                "required": ["snapshot", "node", "acl"],
                "additionalProperties": False,
            },
        ),
    ]


def submit_tool_spec() -> dict:
    """Non-executing candidate-submission schema (REGRESSION_DETECTED only)."""
    return _tool_spec(
        "submit_candidate_patch",
        "Submit one structured candidate patch for Python validation. "
        "Never executes: Python validates against this run's evidence, "
        "assigns the candidate ID, and stores the candidate.",
        CandidateSubmission.model_json_schema(),
    )


def tools_for_verdict(verdict: str) -> list[dict]:
    """Python-side tool registration. The model never widens this list.

    F-05: only REGRESSION_DETECTED registers investigation and submission
    tools. NO_REGRESSION_DETECTED and INCONCLUSIVE are explain-only: no
    tools at all, so the model cannot investigate an untrusted snapshot
    or reach any submission path.
    """
    if verdict == "REGRESSION_DETECTED":
        return [*investigation_tool_specs(), submit_tool_spec()]
    return []


# Transport: (messages, tools) -> {"content": str|None, "tool_calls": [...]}.
# Each tool call: {"id": str, "name": str, "arguments": str (JSON)}.
Transport = Callable[[list[dict], list[dict]], dict]


def default_transport(settings: Settings, http_client: httpx.Client | None = None) -> Transport:
    """OpenAI-compatible Chat Completions transport (Phase 0 observed shape).

    F-06: ``http_client`` is injectable so unit tests can drive the exact
    same code path with a mocked httpx transport. Error messages carry
    only the failure category, never response bodies or credentials.
    """
    url = chat_completions_url(settings)
    headers = auth_headers(settings)
    model = settings.meta_model

    def call(messages: list[dict], tools: list[dict]) -> dict:
        payload: dict = {"model": model, "messages": messages}
        if tools:
            payload["tools"] = tools
        try:
            if http_client is not None:
                resp = http_client.post(url, headers=headers, json=payload)
            else:
                with httpx.Client(timeout=TIMEOUT_S) as client:
                    resp = client.post(url, headers=headers, json=payload)
        except httpx.TimeoutException as exc:
            raise AgentError(
                f"transport_error: timed out ({type(exc).__name__})"
            ) from exc
        except httpx.HTTPError as exc:
            raise AgentError(
                f"transport_error: unreachable ({type(exc).__name__})"
            ) from exc
        if resp.status_code in (401, 403):
            raise AgentError("transport_error: auth_error (401/403)")
        if resp.status_code != 200:
            raise AgentError(f"transport_error: unexpected_response http_{resp.status_code}")
        try:
            body = resp.json()
            choice = body["choices"][0]
            if not isinstance(choice, dict):
                raise TypeError("choice is not an object")
            message = choice["message"]
            if not isinstance(message, dict):
                raise TypeError("message is not an object")
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise AgentError("transport_error: malformed completion body") from exc
        # R-1: finish_reason lives on choices[0] (a sibling of message),
        # not inside the nested message. Only completed responses proceed;
        # a missing value is accepted as before (the observed API always
        # sends one), while any other unexpected value is incomplete.
        finish = choice.get("finish_reason")
        if finish not in (None, "stop", "tool_calls"):
            raise AgentError(f"transport_error: incomplete response (finish_reason={finish!r})")
        calls = []
        tool_calls = message.get("tool_calls") or []
        if not isinstance(tool_calls, list):
            raise AgentError("transport_error: malformed tool call")
        for item in tool_calls:
            try:
                function = item["function"]
                arguments = function.get("arguments") or "{}"
                if not isinstance(arguments, str):
                    raise TypeError("arguments is not a string")
                calls.append(
                    {"id": item["id"], "name": function["name"], "arguments": arguments}
                )
            except (KeyError, TypeError, AttributeError) as exc:
                raise AgentError("transport_error: malformed tool call") from exc
        content = message.get("content")
        return {
            "content": content if isinstance(content, str) else None,
            "tool_calls": calls,
        }

    return call


@dataclass
class _RunContext:
    client: object
    store: EvidenceStore
    intent: Intent
    baseline: SnapshotRef
    proposed: SnapshotRef
    settings: Settings
    # F-12: evidence IDs that already existed when this Stage B invocation
    # started (Stage A records, or records minted by an earlier invocation
    # sharing the store). Candidate validation only honors records minted
    # after this boundary; stale records can neither support nor veto.
    evidence_boundary: frozenset[str] = frozenset()
    candidates: list[CandidatePatch] = field(default_factory=list)
    # F-10: per-RUN (not per-candidate) count of failed submissions.
    # MAX_PATCH_RETRIES therefore grants that many corrective retries per
    # Stage B run: after the budget is spent every further submission is
    # rejected, valid or not. Accepted-candidate capacity stays
    # MAX_CANDIDATES per run.
    submission_failures: int = 0
    activity: list[ToolCallLog] = field(default_factory=list)


def _resolve_snapshot(ctx: _RunContext, role: SnapshotRole) -> SnapshotRef:
    return ctx.baseline if role == SnapshotRole.BASELINE else ctx.proposed


def _resolve_flow(ctx: _RunContext, flow_id: str) -> FlowSpec | None:
    for flow in (*ctx.intent.must_reach, *ctx.intent.must_not_reach):
        if flow.flow_id == flow_id:
            return flow
    return None


def _route_rows_for(ctx: _RunContext, node: str, snapshot_name: str) -> list[dict]:
    """get_routes rows evidencing ``node`` on one snapshot in this run's store.

    F-01: the snapshot identity (``EvidenceRecord.snapshots``) is part of
    the lookup key. Baseline and proposed rows are never pooled, and rows
    from unrelated runs never match. F-12: only records minted after this
    Stage B invocation's evidence boundary count.
    """
    rows: list[dict] = []
    for evidence_id in ctx.store.ids():
        if evidence_id in ctx.evidence_boundary:
            continue
        record = ctx.store.get(evidence_id)
        if record is None or record.tool != "get_routes":
            continue
        if snapshot_name not in record.snapshots:
            continue
        details = record.details
        if details.get("node") != node:
            continue
        routes = details.get("routes")
        if isinstance(routes, list):
            rows.extend(r for r in routes if isinstance(r, dict))
    return rows


def _route_next_hop(row: dict) -> str | None:
    next_hop = row.get("Next_Hop")
    if isinstance(next_hop, dict):
        ip = next_hop.get("ip")
        return ip if isinstance(ip, str) else None
    return next_hop if isinstance(next_hop, str) else None


def _acl_rules_for(ctx: _RunContext, node: str, acl: str, snapshot_name: str) -> list[dict]:
    """get_acl_rules entries evidencing ``node``/``acl`` on one snapshot.

    F-01: only records whose ``EvidenceRecord.snapshots`` include the
    requested snapshot count. ``expected_rule`` matching always runs
    against these same-snapshot rules; no hit from another snapshot is
    ever treated as authoritative. F-12: only records minted after this
    Stage B invocation's evidence boundary count.
    """
    rules: list[dict] = []
    for evidence_id in ctx.store.ids():
        if evidence_id in ctx.evidence_boundary:
            continue
        record = ctx.store.get(evidence_id)
        if record is None or record.tool != "get_acl_rules":
            continue
        if snapshot_name not in record.snapshots:
            continue
        details = record.details
        if details.get("node") != node or details.get("acl") != acl:
            continue
        entries = details.get("rules")
        if isinstance(entries, list):
            rules.extend(r for r in entries if isinstance(r, dict))
    return rules


def _prefix_covers_flow(prefix: str, flow: FlowSpec) -> bool:
    """True when the candidate prefix carries the target flow's destination."""
    try:
        return IPv4Address(str(flow.dst_ip)) in IPv4Network(prefix, strict=False)
    except ValueError:
        return False


def _endpoint_covers(rule_endpoint: str, ip: object) -> bool:
    """True when an ACL endpoint value admits the flow's address."""
    text = rule_endpoint.strip()
    try:
        address = IPv4Address(str(ip))
    except ValueError:
        return False
    if text.lower() == "any":
        return True
    if text.lower().startswith("host "):
        try:
            return IPv4Address(text[5:].strip()) == address
        except ValueError:
            return False
    try:
        if "/" in text:
            return address in IPv4Network(text, strict=False)
        return IPv4Address(text) == address
    except ValueError:
        return False


def _check_route_op(
    ctx: _RunContext, op: AddStaticRoute | RemoveStaticRoute, targets: list[FlowSpec]
) -> list[str]:
    """Evidence + flow binding for one static-route operation.

    F-01: add_static_route draws only on baseline-snapshot evidence,
    remove_static_route only on proposed-snapshot evidence, matched by
    exact node, prefix, and next hop on a static route row. F-03: the
    prefix must additionally cover the destination of at least one
    target flow; rows of other protocols or unrelated prefixes never
    qualify merely because node and next hop match.
    """
    adding = isinstance(op, AddStaticRoute)
    role = "baseline" if adding else "proposed"
    snapshot_name = ctx.baseline.name if adding else ctx.proposed.name
    rows = _route_rows_for(ctx, op.node, snapshot_name)
    exact = [
        row
        for row in rows
        if row.get("Network") == op.prefix
        and _route_next_hop(row) == op.next_hop
        and str(row.get("Protocol", "")).lower() == "static"
    ]
    if not exact:
        return [
            f"no {role} get_routes evidence in this run shows static route "
            f"{op.prefix} via {op.next_hop} on node {op.node!r}; static-route "
            "operations need same-snapshot tool evidence, not general knowledge"
        ]
    if not any(_prefix_covers_flow(op.prefix, flow) for flow in targets):
        return [
            f"prefix {op.prefix} covers the destination of no target flow; "
            "bind the operation to a declared flow it can actually serve"
        ]
    return []


def _check_acl_support(
    ctx: _RunContext, *, node: str, acl: str, sequence: int, expected: AclRule | None
) -> str | None:
    """Evidence support for remove_acl_line (or a freed-sequence permit).

    F-01: only proposed-snapshot ``get_acl_rules`` records count, matched
    against any same-snapshot rule. ``expected`` is the remove_acl_line
    expected_rule; for permit operations it is None (the sequence freed
    by the same-candidate removal is the evidence).
    """
    snapshot_name = ctx.proposed.name
    rules = _acl_rules_for(ctx, node, acl, snapshot_name)
    if not rules:
        return (
            f"no proposed-snapshot get_acl_rules evidence in this run for ACL "
            f"{acl!r} on node {node!r}; call get_acl_rules on the proposed "
            "snapshot before submitting ACL operations"
        )
    hits = [r for r in rules if r.get("sequence_number") == sequence]
    if not hits:
        known = sorted(s for s in {r.get("sequence_number") for r in rules} if isinstance(s, int))
        return (
            f"sequence {sequence} is not evidenced for ACL {acl!r} on node "
            f"{node!r} on the proposed snapshot (evidenced sequences: {known}); "
            "never guess sequences"
        )
    if expected is not None:
        body = {k: hits[0].get(k) for k in ("action", "src", "dst", "protocol", "dst_port")}
        # Evidence details travel as JSON (enums already plain strings).
        if body != expected.model_dump(mode="json"):
            return (
                f"expected_rule does not match the evidenced proposed-snapshot "
                f"rule at sequence {sequence} ({body}); copy the get_acl_rules "
                "rule verbatim"
            )
    return None


def _permit_matches_flow(permit: AclPermit, flow: FlowSpec) -> bool:
    """True when a permit op could serve a must_reach flow (F-02)."""
    if flow.protocol.value.lower() != permit.protocol:
        return False
    if flow.dst_port != permit.dst_port:
        return False
    return _endpoint_covers(permit.src, flow.src_ip) and _endpoint_covers(
        permit.dst, flow.dst_ip
    )


def _check_acl_repair_shape(
    submission: CandidateSubmission,
    acl_ops: list,
    must_reach_targets: list[FlowSpec],
) -> list[str]:
    """Enforce the V1 ACL repair shape in Python (F-02, never via prompts).

    A valid repair is exactly one remove_acl_line for the proposed-snapshot
    deny rule plus one acl_permit at the same freed sequence, matching the
    removed rule's match fields and serving a targeted must_reach flow.
    """
    errors: list[str] = []
    removes = [op for op in acl_ops if isinstance(op, RemoveAclLine)]
    permits = [op for op in acl_ops if isinstance(op, AclPermit)]
    if (
        len(acl_ops) != 2
        or len(removes) != 1
        or len(permits) != 1
        or len(submission.operations) != 2
    ):
        return [
            "V1 ACL repair must be exactly one remove_acl_line plus one "
            "acl_permit (no acl_deny, no extra operations, no route/ACL mix)"
        ]
    remove, permit = removes[0], permits[0]
    if (permit.node, permit.acl, permit.sequence_number) != (
        remove.node,
        remove.acl,
        remove.sequence_number,
    ):
        errors.append(
            "acl_permit must reuse the exact node, ACL, and sequence freed "
            "by the same-candidate remove_acl_line"
        )
    expected = remove.expected_rule
    if expected.action != AclAction.DENY:
        errors.append("remove_acl_line must target the evidenced deny rule")
    elif (
        permit.src != expected.src
        or permit.dst != expected.dst
        or permit.protocol != expected.protocol
        or permit.dst_port != expected.dst_port
    ):
        errors.append(
            "acl_permit must match the removed rule's source, destination, "
            "protocol, and destination port exactly (only the action changes)"
        )
    if not any(_permit_matches_flow(permit, flow) for flow in must_reach_targets):
        errors.append(
            "acl_permit must serve a targeted must_reach flow (protocol, "
            "destination port, and addresses must admit that flow)"
        )
    return errors


def _check_trace_attribution(
    ctx: _RunContext, remove: RemoveAclLine, relevant_flow_ids: list[str]
) -> list[str]:
    """Require trace_flow evidence attributing the denial (F-04, R-2).

    get_acl_rules inventory alone is insufficient: a unique-match trace
    attribution for the relevant flow on the proposed snapshot must name
    the same node, ACL, and sequence the candidate removes.

    R-2: only the specific target must_reach flow(s) the permit serves
    are relevant. Attributions belonging to unrelated flows are ignored
    and can neither support nor veto this candidate. F-12: only trace
    records minted after this Stage B invocation's evidence boundary
    count; stale attributions can neither support nor veto.
    """
    wanted = (remove.node, remove.acl, remove.sequence_number)
    seen_resolutions: set[str] = set()
    agreeing = False
    conflicting: list[tuple] = []
    for evidence_id in ctx.store.ids():
        if evidence_id in ctx.evidence_boundary:
            continue
        record = ctx.store.get(evidence_id)
        if record is None or record.tool != "trace_flow":
            continue
        if record.flow_id not in relevant_flow_ids:
            continue
        if ctx.proposed.name not in record.snapshots:
            continue
        matches = record.details.get("acl_matches")
        if not isinstance(matches, list):
            continue
        for match in matches:
            if not isinstance(match, dict):
                continue
            resolution = match.get("resolution")
            if isinstance(resolution, str):
                seen_resolutions.add(resolution)
            if resolution != "unique-match":
                continue
            triple = (match.get("node"), match.get("filter"), match.get("sequence_number"))
            if triple == wanted:
                agreeing = True
            else:
                conflicting.append(triple)
    if conflicting:
        return [
            f"trace_flow evidence attributes the denial to {conflicting[0]}, "
            f"not to {(remove.node, remove.acl, remove.sequence_number)}; "
            "conflicting attribution cannot support this candidate"
        ]
    if agreeing:
        return []
    observed = sorted(seen_resolutions) or ["no attribution"]
    return [
        "trace_flow evidence does not uniquely attribute the target flow's "
        f"denial to {(remove.node, remove.acl, remove.sequence_number)} "
        f"(observed: {', '.join(observed)}); ACL inventory alone is insufficient"
    ]


def _handle_submission(ctx: _RunContext, args: dict) -> dict:
    """Validate a submit_candidate_patch call; mint the ID only on accept."""
    settings = ctx.settings
    if len(ctx.candidates) >= settings.max_candidates:
        return {
            "accepted": False,
            "errors": [
                f"candidate budget exhausted: MAX_CANDIDATES={settings.max_candidates} "
                "already accepted"
            ],
            "retry_allowed": False,
        }
    if ctx.submission_failures > settings.max_patch_retries:
        return {
            "accepted": False,
            "errors": [
                "submission retry budget exhausted: MAX_PATCH_RETRIES="
                f"{settings.max_patch_retries} corrective retries already used"
            ],
            "retry_allowed": False,
        }
    try:
        submission = TypeAdapter(CandidateSubmission).validate_python(args)
    except ValidationError as exc:
        ctx.submission_failures += 1
        return {
            "accepted": False,
            "errors": [f"schema: {err['loc']}: {err['msg']}" for err in exc.errors()],
            "retry_allowed": ctx.submission_failures <= settings.max_patch_retries,
        }
    errors: list[str] = []
    known_ids = {f.flow_id for f in (*ctx.intent.must_reach, *ctx.intent.must_not_reach)}
    unknown = [fid for fid in submission.target_flow_ids if fid not in known_ids]
    if unknown:
        errors.append(f"unknown target_flow_ids (not in intent): {unknown}")
    if not 1 <= len(submission.operations) <= 5:
        errors.append("operations must hold 1-5 PatchOperations")
    all_flows = (*ctx.intent.must_reach, *ctx.intent.must_not_reach)
    targets = [f for f in all_flows if f.flow_id in submission.target_flow_ids]
    must_reach_targets = [
        f for f in ctx.intent.must_reach if f.flow_id in submission.target_flow_ids
    ]
    route_ops = [
        op
        for op in submission.operations
        if isinstance(op, (AddStaticRoute, RemoveStaticRoute))
    ]
    acl_ops = [
        op
        for op in submission.operations
        if not isinstance(op, (AddStaticRoute, RemoveStaticRoute))
    ]
    for op in route_ops:
        errors.extend(_check_route_op(ctx, op, targets))
    if acl_ops:
        # F-02: the V1 repair shape is enforced before per-op evidence.
        errors.extend(_check_acl_repair_shape(submission, acl_ops, must_reach_targets))
        removes = [op for op in acl_ops if isinstance(op, RemoveAclLine)]
        permits = [op for op in acl_ops if isinstance(op, AclPermit)]
        if len(removes) == 1 and len(acl_ops) == 2 and len(submission.operations) == 2:
            remove = removes[0]
            problem = _check_acl_support(
                ctx,
                node=remove.node,
                acl=remove.acl,
                sequence=remove.sequence_number,
                expected=remove.expected_rule,
            )
            if problem is not None:
                errors.append(problem)
            else:
                # F-01 inventory corroboration passed; F-04/R-2 still
                # require trace attribution of the same rule, scoped to
                # the must_reach flow(s) the permit actually serves.
                relevant = [
                    flow.flow_id
                    for flow in must_reach_targets
                    if permits and _permit_matches_flow(permits[0], flow)
                ]
                errors.extend(_check_trace_attribution(ctx, remove, relevant))
        else:
            for acl_op in acl_ops:
                if isinstance(acl_op, RemoveAclLine):
                    problem = _check_acl_support(
                        ctx,
                        node=acl_op.node,
                        acl=acl_op.acl,
                        sequence=acl_op.sequence_number,
                        expected=acl_op.expected_rule,
                    )
                    if problem is not None:
                        errors.append(problem)
    if errors:
        ctx.submission_failures += 1
        return {
            "accepted": False,
            "errors": errors,
            "retry_allowed": ctx.submission_failures <= settings.max_patch_retries,
        }
    candidate_id = f"c-{len(ctx.candidates) + 1:02d}"
    candidate = CandidatePatch(**submission.model_dump(), candidate_id=candidate_id)
    ctx.candidates.append(candidate)
    return {
        "accepted": True,
        "candidate_id": candidate_id,
        "operations": len(candidate.operations),
    }


def _execute_tool(ctx: _RunContext, name: str, args: dict) -> tuple[dict, str | None]:
    """Run one model-requested tool call. Returns (result_content, evidence_id)."""
    if name == "trace_flow":
        parsed_trace = TypeAdapter(TraceFlowArgs).validate_python(args)
        flow = _resolve_flow(ctx, parsed_trace.flow_id)
        if flow is None:
            raise ValueError(f"unknown flow_id {parsed_trace.flow_id!r}")
        snapshot = _resolve_snapshot(ctx, parsed_trace.snapshot)
        result = trace_flow(ctx.client, ctx.store, flow, snapshot)  # type: ignore[arg-type]
        return result.model_dump(mode="json"), result.evidence_id
    if name == "get_routes":
        parsed_routes = TypeAdapter(GetRoutesArgs).validate_python(args)
        result = get_routes(
            ctx.client,  # type: ignore[arg-type]
            ctx.store,
            _resolve_snapshot(ctx, parsed_routes.snapshot),
            parsed_routes.node,
            parsed_routes.prefix,
        )
        return result.model_dump(mode="json"), result.evidence_id
    if name == "get_acl_rules":
        parsed_acl = TypeAdapter(GetAclRulesArgs).validate_python(args)
        result = get_acl_rules(
            ctx.store, _resolve_snapshot(ctx, parsed_acl.snapshot), parsed_acl.node, parsed_acl.acl
        )
        return result.model_dump(mode="json"), result.evidence_id
    if name == "submit_candidate_patch":
        return _handle_submission(ctx, args), None
    known = ["trace_flow", "get_routes", "get_acl_rules", "submit_candidate_patch"]
    raise ValueError(f"unknown tool {name!r} (known tools: {known})")


def _sanitize_narrative(narrative: str | None, known_ids: set[str]) -> str | None:
    """Hide finding-ID references the Python assessment never minted."""
    if not narrative:
        return narrative

    def scrub(match: re.Match) -> str:
        return match.group(0) if match.group(0) in known_ids else "f-????"

    return re.sub(r"f-\d+", scrub, narrative)


def _run_loop(
    ctx: _RunContext,
    messages: list[dict],
    tools: list[dict],
    transport: Transport,
) -> str | None:
    """Bounded tool-calling loop. Returns the final narrative (possibly None)."""
    budget = ctx.settings.agent_max_tool_calls
    registered = {spec["function"]["name"] for spec in tools}
    used = 0
    narrative: str | None = None
    while True:
        response = transport(messages, tools)
        content = response.get("content")
        if isinstance(content, str) and content.strip():
            narrative = content
        calls = response.get("tool_calls") or []
        if not calls:
            return narrative
        assistant_calls: list[dict] = []
        for idx, raw in enumerate(calls):
            # F-10: tolerate malformed batch entries and mint a unique
            # fallback ID per (admitted-slot, batch-index) pair. Build-time
            # ``used`` is strictly increasing across batches, so fallbacks
            # can never collide with each other.
            item = raw if isinstance(raw, dict) else {}
            call_id = str(item.get("id") or f"local-{used}-{idx}")
            name = str(item.get("name") or "")
            raw_args = item.get("arguments")
            args_text = raw_args if isinstance(raw_args, str) else json.dumps(raw_args or {})
            assistant_calls.append(
                {
                    "id": call_id,
                    "type": "function",
                    "function": {"name": name, "arguments": args_text},
                }
            )
        messages.append({"role": "assistant", "content": content, "tool_calls": assistant_calls})
        for entry in assistant_calls:
            if used >= budget:
                # F-10: the budget is enforced before admitting each call.
                # Calls beyond the budget are neither executed nor logged;
                # the loop ends right after this batch.
                break
            call_id = entry["id"]
            name = entry["function"]["name"]
            args_text = entry["function"]["arguments"]
            try:
                args = json.loads(args_text) if args_text.strip() else {}
            except ValueError:
                args = {"_unparseable": args_text}
            if not isinstance(args, dict):
                args = {"_unparseable": args_text}
            started = time.perf_counter()
            evidence_id: str | None = None
            if name == "submit_candidate_patch" and name not in registered:
                content_out = {
                    "error": "candidates_not_allowed",
                    "detail": "candidate submission is not registered for this verdict",
                }
            elif name not in registered:
                content_out = {
                    "error": "unknown tool",
                    "detail": f"{name!r} is not registered for this verdict",
                }
            else:
                try:
                    content_out, evidence_id = _execute_tool(ctx, name, args)
                except (ValidationError, ValueError) as exc:
                    content_out = {"error": "invalid tool call", "detail": str(exc)}
            latency_ms = (time.perf_counter() - started) * 1000.0
            used += 1
            args_adapter: TypeAdapter[dict[str, JsonValue]] = TypeAdapter(dict[str, JsonValue])
            try:
                logged_args: dict[str, JsonValue] = args_adapter.validate_python(args)
            except ValidationError:
                logged_args = {"_unparseable": args_text}
            ctx.activity.append(
                ToolCallLog(
                    tool=name,
                    args=logged_args,
                    evidence_id=evidence_id,  # type: ignore[arg-type]
                    latency_ms=latency_ms,
                )
            )
            messages.append(
                {"role": "tool", "tool_call_id": call_id, "content": json.dumps(content_out)}
            )
        if used >= budget:
            # Hard stop: never call the model again once the budget is
            # spent, so a model that only emits tool calls cannot loop us.
            if narrative is None:
                narrative = (
                    f"Investigation stopped: AGENT_MAX_TOOL_CALLS={budget} exhausted "
                    "before Muse produced a summary."
                )
            return narrative
    # unreachable: loop only exits via return


def run_stage_b(
    client: object,
    store: EvidenceStore,
    assessment: AssessmentResult,
    intent: Intent,
    baseline: SnapshotRef,
    proposed: SnapshotRef,
    *,
    question: str = "",
    settings: Settings | None = None,
    transport: Transport | None = None,
) -> InvestigationResult:
    """Run verdict-gated Muse investigation. Never raises, never mutates Stage A."""
    resolved = settings if settings is not None else load_settings()
    ctx = _RunContext(
        client=client,
        store=store,
        intent=intent,
        baseline=baseline,
        proposed=proposed,
        settings=resolved,
        # F-12: freeze the pre-existing evidence IDs now, before any
        # investigation tool mints records for this invocation.
        evidence_boundary=frozenset(store.ids()),
    )
    try:
        if resolved.candidate_submission_variant != "tool":
            raise AgentError(
                f"unsupported CANDIDATE_SUBMISSION_VARIANT="
                f"{resolved.candidate_submission_variant!r}: Phase 3 requires 'tool'"
            )
        if transport is None:
            if resolved.meta_api_key is None:
                return InvestigationResult(
                    narrative="Stage B skipped: META_API_KEY is not configured.",
                    candidates=[],
                    tool_activity=[],
                )
            transport = default_transport(resolved)
        allow_candidates = assessment.verdict == "REGRESSION_DETECTED"
        tools = tools_for_verdict(assessment.verdict)
        messages: list[dict] = [
            {
                "role": "system",
                "content": prompts.build_system_prompt(
                    verdict=assessment.verdict, allow_candidates=allow_candidates
                ),
            },
            {
                "role": "user",
                "content": prompts.build_user_context(assessment, intent, question=question),
            },
        ]
        narrative = _run_loop(ctx, messages, tools, transport)
        known_ids = {f.finding_id for f in assessment.findings}
        return InvestigationResult(
            narrative=_sanitize_narrative(narrative, known_ids),
            candidates=ctx.candidates,
            tool_activity=ctx.activity,
        )
    except AgentError as exc:
        return InvestigationResult(
            narrative=f"Stage B failed: {exc}",
            candidates=list(ctx.candidates),
            tool_activity=list(ctx.activity),
        )
    except Exception as exc:  # last resort: Stage A output must survive
        return InvestigationResult(
            narrative=f"Stage B failed: unexpected {type(exc).__name__}: {exc}",
            candidates=list(ctx.candidates),
            tool_activity=list(ctx.activity),
        )
