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
from typing import Callable

import httpx
from pydantic import TypeAdapter, ValidationError

from netops_lens import prompts
from netops_lens.config import Settings, auth_headers, chat_completions_url, load_settings
from netops_lens.evidence import EvidenceStore
from netops_lens.models import (
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
    """Python-side tool registration. The model never widens this list."""
    if verdict == "REGRESSION_DETECTED":
        return [*investigation_tool_specs(), submit_tool_spec()]
    if verdict == "NO_REGRESSION_DETECTED":
        return investigation_tool_specs()
    return []


# Transport: (messages, tools) -> {"content": str|None, "tool_calls": [...]}.
# Each tool call: {"id": str, "name": str, "arguments": str (JSON)}.
Transport = Callable[[list[dict], list[dict]], dict]


def default_transport(settings: Settings) -> Transport:
    """OpenAI-compatible Chat Completions transport (Phase 0 observed shape)."""
    url = chat_completions_url(settings)
    headers = auth_headers(settings)
    model = settings.meta_model

    def call(messages: list[dict], tools: list[dict]) -> dict:
        payload: dict = {"model": model, "messages": messages}
        if tools:
            payload["tools"] = tools
        try:
            with httpx.Client(timeout=TIMEOUT_S) as client:
                resp = client.post(url, headers=headers, json=payload)
        except httpx.TimeoutException as exc:
            raise AgentError(f"transport_error: Meta API request timed out: {exc}") from exc
        except httpx.HTTPError as exc:
            raise AgentError(f"transport_error: Meta API unreachable: {exc}") from exc
        if resp.status_code in (401, 403):
            raise AgentError("transport_error: auth_error (401/403)")
        if resp.status_code != 200:
            raise AgentError(f"transport_error: unexpected_response http_{resp.status_code}")
        try:
            message = resp.json()["choices"][0]["message"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise AgentError("transport_error: malformed completion body") from exc
        calls = []
        for item in message.get("tool_calls") or []:
            try:
                function = item["function"]
                calls.append(
                    {
                        "id": item["id"],
                        "name": function["name"],
                        "arguments": function.get("arguments") or "{}",
                    }
                )
            except (KeyError, TypeError) as exc:
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
    candidates: list[CandidatePatch] = field(default_factory=list)
    submission_failures: int = 0
    activity: list[ToolCallLog] = field(default_factory=list)


def _resolve_snapshot(ctx: _RunContext, role: SnapshotRole) -> SnapshotRef:
    return ctx.baseline if role == SnapshotRole.BASELINE else ctx.proposed


def _resolve_flow(ctx: _RunContext, flow_id: str) -> FlowSpec | None:
    for flow in (*ctx.intent.must_reach, *ctx.intent.must_not_reach):
        if flow.flow_id == flow_id:
            return flow
    return None


def _route_rows_for(ctx: _RunContext, node: str) -> list[dict]:
    """All get_routes route rows evidencing ``node`` in this run's store."""
    rows: list[dict] = []
    for evidence_id in ctx.store.ids():
        record = ctx.store.get(evidence_id)
        if record is None or record.tool != "get_routes":
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


def _acl_rules_for(ctx: _RunContext, node: str, acl: str) -> list[dict]:
    """All get_acl_rules rule entries evidencing ``node``/``acl`` this run."""
    rules: list[dict] = []
    for evidence_id in ctx.store.ids():
        record = ctx.store.get(evidence_id)
        if record is None or record.tool != "get_acl_rules":
            continue
        details = record.details
        if details.get("node") != node or details.get("acl") != acl:
            continue
        entries = details.get("rules")
        if isinstance(entries, list):
            rules.extend(r for r in entries if isinstance(r, dict))
    return rules


def _check_route_support(ctx: _RunContext, *, node: str, prefix: str, next_hop: str) -> str | None:
    """Evidence support for add/remove_static_route; None when supported."""
    for row in _route_rows_for(ctx, node):
        if row.get("Network") == prefix and _route_next_hop(row) == next_hop:
            return None
    return (
        f"no get_routes evidence in this run shows {prefix} via {next_hop} "
        f"on node {node!r}; static-route operations need tool evidence, "
        "not general knowledge"
    )


def _check_acl_support(
    ctx: _RunContext, *, node: str, acl: str, sequence: int, expected: AclRule | None
) -> str | None:
    """Evidence support for acl_permit/acl_deny/remove_acl_line.

    ``expected`` is the remove_acl_line expected_rule, or None for
    permit/deny operations (the freed sequence itself is the evidence).
    """
    rules = _acl_rules_for(ctx, node, acl)
    if not rules:
        return (
            f"no get_acl_rules evidence in this run for ACL {acl!r} on node "
            f"{node!r}; call get_acl_rules before submitting ACL operations"
        )
    hits = [r for r in rules if r.get("sequence_number") == sequence]
    if not hits:
        known = sorted(s for s in {r.get("sequence_number") for r in rules} if isinstance(s, int))
        return (
            f"sequence {sequence} is not evidenced for ACL {acl!r} on node "
            f"{node!r} (evidenced sequences: {known}); never guess sequences"
        )
    if expected is not None:
        body = {k: hits[0].get(k) for k in ("action", "src", "dst", "protocol", "dst_port")}
        # Evidence details travel as JSON (enums already plain strings).
        if body != expected.model_dump(mode="json"):
            return (
                f"expected_rule does not match the evidenced rule at sequence "
                f"{sequence} ({body}); copy the get_acl_rules rule verbatim"
            )
    return None


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
    for op in submission.operations:
        if isinstance(op, (AddStaticRoute, RemoveStaticRoute)):
            problem = _check_route_support(
                ctx, node=op.node, prefix=op.prefix, next_hop=op.next_hop
            )
        else:
            problem = _check_acl_support(
                ctx,
                node=op.node,
                acl=op.acl,
                sequence=op.sequence_number,
                expected=op.expected_rule if isinstance(op, RemoveAclLine) else None,
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
        for item in calls:
            call_id = str(item.get("id") or f"call-{used}")
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
            if used >= budget:
                content_out: dict = {
                    "error": "tool budget exhausted",
                    "detail": f"AGENT_MAX_TOOL_CALLS={budget} already used",
                }
            elif name == "submit_candidate_patch" and name not in registered:
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
