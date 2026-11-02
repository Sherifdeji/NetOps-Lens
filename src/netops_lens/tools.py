"""The six backend tools. Only caller of batfish_client. No Pybatfish import.

Every tool returns a typed ``ToolResult`` and mints exactly one evidence
record per invocation (success, error, and inconclusive alike). Tool
arguments are Pydantic-validated before any Batfish call; failures surface
as typed results, never as exceptions across the tool boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Network
from typing import Annotated

from pydantic import Field, TypeAdapter

from netops_lens.acl_parser import AclParseError, load_node_acl, parse_acl_rule_line
from netops_lens.batfish_client import BatfishClient, BatfishError
from netops_lens.evidence import EvidenceStore
from netops_lens.models import (
    FlowSpec,
    Reachability,
    SnapshotHealth,
    SnapshotRef,
    ToolResult,
)

NonEmptyStr = Annotated[str, Field(min_length=1)]
_str_adapter: TypeAdapter[str] = TypeAdapter(NonEmptyStr)

BENIGN_WARNING_ALLOWLIST: tuple[str, ...] = ()
"""Exact initIssues signatures known harmless. Empty: Phase 1 evidenced none."""


@dataclass(frozen=True)
class IntentOutcome:
    reachability: Reachability
    batfish_disposition: str | None


@dataclass(frozen=True)
class DifferentialOutcome:
    reported_changed: bool
    snapshot_reach: Reachability | None
    reference_reach: Reachability | None
    snapshot_trace_total: int
    reference_trace_total: int
    query_ok: bool
    conclusive: bool
    snapshot_reported_total: int | None = None
    reference_reported_total: int | None = None
    incomplete_reason: str | None = None


def _check_args(flow: FlowSpec, snapshot: SnapshotRef) -> tuple[FlowSpec, SnapshotRef]:
    flow_adapter: TypeAdapter[FlowSpec] = TypeAdapter(FlowSpec)
    snapshot_adapter: TypeAdapter[SnapshotRef] = TypeAdapter(SnapshotRef)
    return flow_adapter.validate_python(flow), snapshot_adapter.validate_python(snapshot)


def _cell_list(row: dict, key: str) -> list:
    value = row.get(key)
    return value if isinstance(value, list) else []


def _cell_dict(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _cell_str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _cell_count(value: object) -> int | None:
    """A reported TraceCount is valid only as a non-negative plain int."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _side_completeness(
    rows: list, traces_key: str, count_key: str
) -> tuple[bool, int | None, int, str | None]:
    """Per-side trace completeness.

    The reported total is the side's authoritative count: exactly one
    distinct valid value must appear across rows, and the summed returned
    traces must equal it. Returns (complete, reported_total, returned_total,
    problem) where problem is "truncated", "uncertain", or None. Missing,
    invalid, or inconsistent counts are never treated as complete; neither
    is any shortfall. Unequal snapshot/reference totals are fine — each side
    is judged independently.
    """
    returned = 0
    reported_values: list[int] = []
    for row in rows:
        if not isinstance(row, dict):
            return False, None, returned, "uncertain"
        traces = row.get(traces_key)
        if not isinstance(traces, list):
            return False, None, returned, "uncertain"
        returned += len(traces)
        count = _cell_count(row.get(count_key))
        if count is None:
            return False, None, returned, "uncertain"
        reported_values.append(count)
    if len(set(reported_values)) != 1:
        return False, None, returned, "uncertain"
    reported = reported_values[0]
    if returned != reported:
        return False, reported, returned, "truncated"
    return True, reported, returned, None


def _mint(
    store: EvidenceStore,
    *,
    tool: str,
    snapshots: list[str],
    status: str,
    summary: str,
    details: dict,
    flow_id: str | None = None,
    disposition: str | None = None,
) -> ToolResult:
    payload = dict(details)
    payload["tool_status"] = status
    evidence_id = store.record(
        tool=tool,
        snapshots=snapshots,
        flow_id=flow_id,
        disposition=disposition,
        details=payload,
    )
    return ToolResult(
        tool=tool,
        snapshots=snapshots,
        flow_id=flow_id,
        status=status,  # type: ignore[arg-type]
        summary=summary,
        details=payload,
        evidence_id=evidence_id,  # type: ignore[arg-type]
    )


def _batfish_reachability(disposition: str | None) -> Reachability:
    if disposition == "ACCEPTED":
        return "REACHABLE"
    if disposition == "NO_ROUTE" or (disposition or "").startswith("DENIED"):
        return "UNREACHABLE"
    return "UNKNOWN"


def get_snapshot_health(
    client: BatfishClient,
    store: EvidenceStore,
    snapshot: SnapshotRef,
    *,
    expected_nodes: tuple[str, ...] = ("r1", "r2"),
) -> tuple[ToolResult, SnapshotHealth]:
    """Combine fileParseStatus + initIssues + nodeProperties into a verdict."""
    snapshot = TypeAdapter(SnapshotRef).validate_python(snapshot)
    try:
        records = client.health_records(snapshot.name)
    except BatfishError as exc:
        health = SnapshotHealth(
            snapshot=snapshot.name, status="NOT_OK", reasons=(f"health query failed: {exc}",)
        )
        result = _mint(
            store,
            tool="get_snapshot_health",
            snapshots=[snapshot.name],
            status="error",
            summary=f"NOT_OK: {health.reasons[0]}",
            details={"error": str(exc)},
        )
        return result, health

    reasons: list[str] = []
    per_file = []
    for row in records.parse_status:
        per_file.append({"file": row.get("File_Name"), "status": row.get("Status")})
        if row.get("Status") != "PASSED":
            reasons.append(
                f"{row.get('File_Name')}: parse status {row.get('Status')!r} "
                f"(format {row.get('File_Format')!r})"
            )
    init_details: list[str] = []
    for row in records.init_issues:
        text = (
            f"[{row.get('Type')}] {row.get('Details')} "
            f"(lines: {row.get('Source_Lines')}; text: {row.get('Line_Text')!r}; "
            f"nodes: {row.get('Nodes')}; context: {row.get('Parser_Context')})"
        )
        init_details.append(text)
        if text not in BENIGN_WARNING_ALLOWLIST:
            reasons.append(f"init issue: {text}")
    benign = [t for t in init_details if t in BENIGN_WARNING_ALLOWLIST]
    nodes = sorted({str(r.get("Node")) for r in records.nodes if r.get("Node")})
    if not nodes:
        reasons.append("no nodes recognized")
    else:
        missing = [n for n in expected_nodes if n not in nodes]
        if missing:
            reasons.append(f"expected node(s) absent: {', '.join(missing)}")

    if reasons:
        health = SnapshotHealth(snapshot=snapshot.name, status="NOT_OK", reasons=tuple(reasons))
        summary = f"NOT_OK: {len(reasons)} blocking reason(s)"
    else:
        health = SnapshotHealth(snapshot=snapshot.name, status="OK")
        summary = f"OK: {len(per_file)} file(s) parsed, nodes {', '.join(nodes)}" + (
            f", {len(benign)} benign warning(s)" if benign else ""
        )
        if benign:
            health = SnapshotHealth(
                snapshot=snapshot.name, status="OK", benign_warnings=tuple(benign)
            )
    result = _mint(
        store,
        tool="get_snapshot_health",
        snapshots=[snapshot.name],
        status="ok",
        summary=summary,
        details={
            "health": health.model_dump(mode="json"),
            "parse_status": list(records.parse_status),
            "init_issues": list(records.init_issues),
            "nodes": list(records.nodes),
        },
    )
    return result, health


def _headers_for(client: BatfishClient, flow: FlowSpec):
    return client.flow_headers(
        src_ip=str(flow.src_ip),
        dst_ip=str(flow.dst_ip),
        protocol=flow.protocol.value,
        dst_port=flow.dst_port,
    )


def check_intent(
    client: BatfishClient,
    store: EvidenceStore,
    flow: FlowSpec,
    snapshot: SnapshotRef,
) -> tuple[ToolResult, IntentOutcome]:
    """Return the per-flow disposition on one snapshot (REACHABLE/UNREACHABLE/UNKNOWN)."""
    flow, snapshot = _check_args(flow, snapshot)
    try:
        rows = client.ask(
            "traceroute",
            snapshot.name,
            headers=_headers_for(client, flow),
            startLocation=flow.start_location,
        )
    except BatfishError as exc:
        result = _mint(
            store,
            tool="check_intent",
            snapshots=[snapshot.name],
            flow_id=flow.flow_id,
            status="inconclusive",
            summary=f"UNKNOWN: traceroute query failed: {exc}",
            details={"error": str(exc)},
        )
        return result, IntentOutcome(reachability="UNKNOWN", batfish_disposition=None)
    if not rows:
        result = _mint(
            store,
            tool="check_intent",
            snapshots=[snapshot.name],
            flow_id=flow.flow_id,
            status="inconclusive",
            summary="UNKNOWN: traceroute returned no rows",
            details={"error": "empty traceroute answer"},
        )
        return result, IntentOutcome(reachability="UNKNOWN", batfish_disposition=None)
    traces = _cell_list(rows[0], "Traces")
    first = _cell_dict(traces[0]) if traces else {}
    disposition = _cell_str(first.get("disposition"))
    reachability = _batfish_reachability(disposition)
    outcome = IntentOutcome(
        reachability=reachability,
        batfish_disposition=disposition,
    )
    result = _mint(
        store,
        tool="check_intent",
        snapshots=[snapshot.name],
        flow_id=flow.flow_id,
        status="ok",
        summary=f"{reachability} ({outcome.batfish_disposition})",
        details={
            "batfish_disposition": outcome.batfish_disposition,
            "reachability": reachability,
            "trace_count": rows[0].get("TraceCount"),
            "traces": traces,
        },
        disposition=outcome.batfish_disposition,
    )
    return result, outcome


def compare_snapshots(
    client: BatfishClient,
    store: EvidenceStore,
    flow: FlowSpec,
    baseline: SnapshotRef,
    proposed: SnapshotRef,
) -> tuple[ToolResult, DifferentialOutcome]:
    """Cross-check one flow: does Batfish report it as changed?

    An absent row means "not reported changed" — never proven unchanged.
    """
    flow_adapter: TypeAdapter[FlowSpec] = TypeAdapter(FlowSpec)
    ref_adapter: TypeAdapter[SnapshotRef] = TypeAdapter(SnapshotRef)
    flow = flow_adapter.validate_python(flow)
    baseline = ref_adapter.validate_python(baseline)
    proposed = ref_adapter.validate_python(proposed)
    try:
        rows = client.ask(
            "differentialReachability",
            proposed.name,
            reference_snapshot=baseline.name,
            pathConstraints=client.start_path(flow.start_location),
            headers=_headers_for(client, flow),
            maxTraces=5,
        )
    except BatfishError as exc:
        result = _mint(
            store,
            tool="compare_snapshots",
            snapshots=[baseline.name, proposed.name],
            flow_id=flow.flow_id,
            status="inconclusive",
            summary=f"differential unknown: query failed: {exc}",
            details={"error": str(exc)},
        )
        return result, DifferentialOutcome(
            False, None, None, 0, 0, query_ok=False, conclusive=False
        )
    if not rows:
        result = _mint(
            store,
            tool="compare_snapshots",
            snapshots=[baseline.name, proposed.name],
            flow_id=flow.flow_id,
            status="ok",
            summary="not reported changed (absent row proves nothing)",
            details={"reported_changed": False, "rows": []},
            disposition="NOT_REPORTED",
        )
        return result, DifferentialOutcome(False, None, None, 0, 0, query_ok=True, conclusive=True)
    try:
        snapshot_disps: list[str | None] = []
        reference_disps: list[str | None] = []
        for row in rows:
            for trace in _cell_list(row, "Snapshot_Traces"):
                snapshot_disps.append(_cell_str(_cell_dict(trace).get("disposition")))
            for trace in _cell_list(row, "Reference_Traces"):
                reference_disps.append(_cell_str(_cell_dict(trace).get("disposition")))
        if not snapshot_disps or not reference_disps:
            raise KeyError("traces")
        snapshot_reaches = {_batfish_reachability(d) for d in snapshot_disps}
        reference_reaches = {_batfish_reachability(d) for d in reference_disps}
    except KeyError, IndexError, TypeError, AttributeError:
        result = _mint(
            store,
            tool="compare_snapshots",
            snapshots=[baseline.name, proposed.name],
            flow_id=flow.flow_id,
            status="inconclusive",
            summary="differential unknown: unexpected answer shape",
            details={"error": "unexpected differentialReachability shape", "rows": rows},
        )
        return result, DifferentialOutcome(
            bool(rows), None, None, 0, 0, query_ok=False, conclusive=False
        )
    snap_complete, snap_reported, snap_returned, snap_problem = _side_completeness(
        rows, "Snapshot_Traces", "Snapshot_TraceCount"
    )
    ref_complete, ref_reported, ref_returned, ref_problem = _side_completeness(
        rows, "Reference_Traces", "Reference_TraceCount"
    )
    if not (snap_complete and ref_complete):
        problems = []
        if snap_problem == "truncated" or ref_problem == "truncated":
            problems.append(
                f"trace truncation: snapshot returned {snap_returned} of reported "
                f"{snap_reported}; reference returned {ref_returned} of reported "
                f"{ref_reported}"
            )
        if snap_problem == "uncertain" or ref_problem == "uncertain":
            problems.append("trace count uncertain: missing, invalid, or inconsistent counts")
        reason = "; ".join(problems)
        result = _mint(
            store,
            tool="compare_snapshots",
            snapshots=[baseline.name, proposed.name],
            flow_id=flow.flow_id,
            status="inconclusive",
            summary=f"differential inconclusive: {reason}",
            details={
                "reported_changed": True,
                "snapshot_dispositions": snapshot_disps,
                "reference_dispositions": reference_disps,
                "snapshot_trace_total": snap_returned,
                "reference_trace_total": ref_returned,
                "snapshot_reported_total": snap_reported,
                "reference_reported_total": ref_reported,
                "snapshot_complete": snap_complete,
                "reference_complete": ref_complete,
                "incomplete_reason": reason,
                "rows": rows,
            },
            disposition="TRUNCATED" if "truncation" in reason else "COUNT_UNCERTAIN",
        )
        return result, DifferentialOutcome(
            True,
            None,
            None,
            snap_returned,
            ref_returned,
            query_ok=True,
            conclusive=False,
            snapshot_reported_total=snap_reported,
            reference_reported_total=ref_reported,
            incomplete_reason=reason,
        )
    snapshot_agreed = len(snapshot_reaches) == 1 and "UNKNOWN" not in snapshot_reaches
    reference_agreed = len(reference_reaches) == 1 and "UNKNOWN" not in reference_reaches
    if not (snapshot_agreed and reference_agreed):
        result = _mint(
            store,
            tool="compare_snapshots",
            snapshots=[baseline.name, proposed.name],
            flow_id=flow.flow_id,
            status="inconclusive",
            summary="differential ambiguous: traces do not establish one result",
            details={
                "reported_changed": True,
                "snapshot_dispositions": snapshot_disps,
                "reference_dispositions": reference_disps,
                "snapshot_trace_total": snap_returned,
                "reference_trace_total": ref_returned,
                "snapshot_reported_total": snap_reported,
                "reference_reported_total": ref_reported,
                "snapshot_complete": snap_complete,
                "reference_complete": ref_complete,
                "rows": rows,
            },
            disposition="AMBIGUOUS",
        )
        return result, DifferentialOutcome(
            True,
            None,
            None,
            snap_returned,
            ref_returned,
            query_ok=True,
            conclusive=False,
            snapshot_reported_total=snap_reported,
            reference_reported_total=ref_reported,
        )
    snapshot_reach = next(iter(snapshot_reaches))
    reference_reach = next(iter(reference_reaches))
    outcome = DifferentialOutcome(
        True,
        snapshot_reach,
        reference_reach,
        snap_returned,
        ref_returned,
        query_ok=True,
        conclusive=True,
        snapshot_reported_total=snap_reported,
        reference_reported_total=ref_reported,
    )
    result = _mint(
        store,
        tool="compare_snapshots",
        snapshots=[baseline.name, proposed.name],
        flow_id=flow.flow_id,
        status="ok",
        summary=f"reported changed: {reference_reach} -> {snapshot_reach}",
        details={
            "reported_changed": True,
            "snapshot_dispositions": snapshot_disps,
            "reference_dispositions": reference_disps,
            "snapshot_trace_total": snap_returned,
            "reference_trace_total": ref_returned,
            "snapshot_reported_total": snap_reported,
            "reference_reported_total": ref_reported,
            "snapshot_complete": True,
            "reference_complete": True,
            "rows": rows,
        },
        disposition="CHANGED",
    )
    return result, outcome


def trace_flow(
    client: BatfishClient,
    store: EvidenceStore,
    flow: FlowSpec,
    snapshot: SnapshotRef,
) -> ToolResult:
    """Ordered hops with dispositions; ACL attribution via testFilters + parser.

    IOS sequence numbers come only from the config parser after content
    reconciliation. Batfish exposes no Line_Index here, so that provenance
    field is recorded as None rather than inferred.
    """
    flow, snapshot = _check_args(flow, snapshot)
    try:
        rows = client.ask(
            "traceroute",
            snapshot.name,
            headers=_headers_for(client, flow),
            startLocation=flow.start_location,
        )
    except BatfishError as exc:
        return _mint(
            store,
            tool="trace_flow",
            snapshots=[snapshot.name],
            flow_id=flow.flow_id,
            status="error",
            summary=f"traceroute query failed: {exc}",
            details={"error": str(exc)},
        )
    if not rows:
        return _mint(
            store,
            tool="trace_flow",
            snapshots=[snapshot.name],
            flow_id=flow.flow_id,
            status="error",
            summary="traceroute returned no rows",
            details={"error": "empty traceroute answer"},
        )
    traces = _cell_list(rows[0], "Traces")
    first = _cell_dict(traces[0]) if traces else {}
    final = _cell_str(first.get("disposition"))
    hops = _cell_list(first, "hops")
    acl_matches: list[dict] = []
    for hop in hops:
        hop_record = _cell_dict(hop)
        for step in _cell_list(hop_record, "steps"):
            step_record = _cell_dict(step)
            if step_record.get("action") != "DENIED":
                continue
            detail = _cell_dict(step_record.get("detail"))
            filter_name = _cell_str(detail.get("filter"))
            if filter_name is None:
                continue
            acl_matches.append(
                _identify_filter(
                    client,
                    flow,
                    snapshot_name=snapshot.name,
                    snapshot_path=snapshot.path,
                    node=str(hop_record.get("node")),
                    filter_name=filter_name,
                )
            )
    return _mint(
        store,
        tool="trace_flow",
        snapshots=[snapshot.name],
        flow_id=flow.flow_id,
        status="ok",
        summary=f"final disposition {final}",
        details={
            "final_disposition": final,
            "hops": hops,
            "acl_matches": acl_matches,
        },
        disposition=final if isinstance(final, str) else None,
    )


def _identify_filter(
    client: BatfishClient,
    flow: FlowSpec,
    *,
    snapshot_name: str,
    snapshot_path: str,
    node: str,
    filter_name: str,
) -> dict:
    """Reconcile one DENIED step against testFilters + the config parser."""
    specifier = f"{node}[{filter_name}]"
    try:
        rows = client.ask(
            "testFilters",
            snapshot_name,
            headers=_headers_for(client, flow),
            filters=specifier,
        )
    except BatfishError as exc:
        return {
            "node": node,
            "filter": filter_name,
            "resolution": "testfilters-unavailable",
            "reason": str(exc),
        }
    matches = []
    for row in rows:
        content = _cell_str(row.get("Line_Content"))
        if content is None:
            continue
        try:
            parsed = parse_acl_rule_line(content)
        except AclParseError:
            continue
        sequence: int | None = None
        source: str | None = None
        try:
            rules = load_node_acl(snapshot_path, node, filter_name)
            hits = [r.sequence_number for r in rules if r.rule == parsed.rule]
            if len(hits) == 1:
                sequence, source = hits[0], "config-parser"
        except AclParseError:
            pass
        matches.append(
            {
                "node": node,
                "filter": filter_name,
                "action": row.get("Action"),
                "matched_line_content": content,
                "batfish_line_index": None,
                "sequence_number": sequence,
                "sequence_source": source,
            }
        )
    if not matches:
        return {
            "node": node,
            "filter": filter_name,
            "resolution": "unresolved",
            "reason": "testFilters named the filter but no rule line reconciled",
        }
    if len(matches) > 1:
        for match in matches:
            match["resolution"] = "ambiguous"
        return {
            "node": node,
            "filter": filter_name,
            "resolution": "ambiguous",
            "reason": "multiple candidate rules; refusing to guess",
            "candidates": matches,
        }
    matches[0]["resolution"] = (
        "unique-match" if matches[0]["sequence_number"] is not None else "unresolved"
    )
    return matches[0]


def get_routes(
    client: BatfishClient,
    store: EvidenceStore,
    snapshot: SnapshotRef,
    node: str,
    prefix: str | None = None,
) -> ToolResult:
    """Structured route table for one node. Missing node is an error."""
    snapshot = TypeAdapter(SnapshotRef).validate_python(snapshot)
    node = _str_adapter.validate_python(node)
    network: str | None = None
    if prefix is not None:
        try:
            network = str(IPv4Network(prefix, strict=False))
        except ValueError as exc:
            return _mint(
                store,
                tool="get_routes",
                snapshots=[snapshot.name],
                status="error",
                summary=f"invalid prefix {prefix!r}",
                details={"error": str(exc)},
            )
    try:
        if network is None:
            rows = client.ask("routes", snapshot.name, nodes=node)
        else:
            rows = client.ask("routes", snapshot.name, nodes=node, network=network)
    except BatfishError as exc:
        return _mint(
            store,
            tool="get_routes",
            snapshots=[snapshot.name],
            status="error",
            summary=f"routes query failed for node {node!r}: {exc}",
            details={"error": str(exc)},
        )
    if rows:
        return _mint(
            store,
            tool="get_routes",
            snapshots=[snapshot.name],
            status="ok",
            summary=f"{len(rows)} route(s) on node {node}",
            details={"node": node, "route_found": True, "route_count": len(rows), "routes": rows},
        )
    try:
        inventory = client.ask("nodeProperties", snapshot.name)
    except BatfishError as exc:
        return _mint(
            store,
            tool="get_routes",
            snapshots=[snapshot.name],
            status="error",
            summary=f"cannot verify node {node!r}: node inventory failed: {exc}",
            details={"error": str(exc)},
        )
    if node not in {row.get("Node") for row in inventory}:
        return _mint(
            store,
            tool="get_routes",
            snapshots=[snapshot.name],
            status="error",
            summary=f"unknown node {node!r} on snapshot {snapshot.name!r}",
            details={"error": f"unknown node {node!r}", "route_count": 0},
        )
    return _mint(
        store,
        tool="get_routes",
        snapshots=[snapshot.name],
        status="ok",
        summary=f"node {node} exists; no route matches" + (f" prefix {network}" if network else ""),
        details={
            "node": node,
            "route_found": False,
            "route_count": 0,
            "routes": [],
        },
    )


def get_acl_rules(
    store: EvidenceStore,
    snapshot: SnapshotRef,
    node: str,
    acl: str,
) -> ToolResult:
    """Parse the named extended ACL from the snapshot's config (no Batfish)."""
    snapshot = TypeAdapter(SnapshotRef).validate_python(snapshot)
    node = _str_adapter.validate_python(node)
    acl = _str_adapter.validate_python(acl)
    try:
        rules = load_node_acl(snapshot.path, node, acl)
    except AclParseError as exc:
        return _mint(
            store,
            tool="get_acl_rules",
            snapshots=[snapshot.name],
            status="error",
            summary=f"ACL parse failed: {exc}",
            details={"error": str(exc)},
        )
    return _mint(
        store,
        tool="get_acl_rules",
        snapshots=[snapshot.name],
        status="ok",
        summary=f"ACL {acl!r} on {node}: {len(rules)} rule(s)",
        details={
            "node": node,
            "acl": acl,
            "rule_count": len(rules),
            "rules": [
                {
                    "sequence_number": r.sequence_number,
                    "action": r.rule.action.value,
                    "src": r.rule.src,
                    "dst": r.rule.dst,
                    "protocol": r.rule.protocol,
                    "dst_port": r.rule.dst_port,
                    "raw_line": r.raw_line,
                }
                for r in rules
            ],
        },
    )
