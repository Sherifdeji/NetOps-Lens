"""The six backend tools. Only caller of batfish_client. No Pybatfish import.

Every tool returns a typed ``ToolResult`` and mints exactly one evidence
record per invocation (success, error, and inconclusive alike). Tool
arguments are Pydantic-validated before any Batfish call; failures surface
as typed results, never as exceptions across the tool boundary.
"""

from __future__ import annotations

import re
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
    out_of_scope: tuple = ()


def _check_args(flow: FlowSpec, snapshot: SnapshotRef) -> tuple[FlowSpec, SnapshotRef]:
    flow_adapter: TypeAdapter[FlowSpec] = TypeAdapter(FlowSpec)
    snapshot_adapter: TypeAdapter[SnapshotRef] = TypeAdapter(SnapshotRef)
    return flow_adapter.validate_python(flow), snapshot_adapter.validate_python(snapshot)


_START_LOCATION_RE = re.compile(r"^@enter\(([^[]+)\[([^\]]+)\]\)$")


def _parse_start_location(start_location: str) -> tuple[str, str] | None:
    """Split ``@enter(node[iface])``; None when the shape is unrecognized."""
    match = _START_LOCATION_RE.match(start_location.strip())
    if match is None:
        return None
    return match.group(1), match.group(2)


def _match_flow(flow: FlowSpec, row_flow: object) -> tuple[bool, str | None]:
    """Check a returned Flow object against the requested FlowSpec.

    Compares source IP, destination IP, protocol, destination port (when the
    FlowSpec pins one), and start location. The ephemeral source port is
    explicitly ignored. Returns (matched, reason_if_not).
    """
    if not isinstance(row_flow, dict):
        return False, "row has no Flow identity"
    if str(row_flow.get("srcIp")) != str(flow.src_ip):
        return False, f"srcIp {row_flow.get('srcIp')!r} is not the requested flow"
    if str(row_flow.get("dstIp")) != str(flow.dst_ip):
        return False, f"dstIp {row_flow.get('dstIp')!r} is not the requested flow"
    if str(row_flow.get("ipProtocol", "")).upper() != flow.protocol.value:
        return False, f"protocol {row_flow.get('ipProtocol')!r} is not the requested flow"
    if flow.dst_port is not None and row_flow.get("dstPort") != flow.dst_port:
        return False, f"dstPort {row_flow.get('dstPort')!r} is not the requested flow"
    start = _parse_start_location(flow.start_location)
    if start is None:
        return False, f"start location {flow.start_location!r} is not parseable"
    node, iface = start
    if row_flow.get("ingressNode") != node or row_flow.get("ingressInterface") != iface:
        return False, (
            f"ingress {row_flow.get('ingressNode')!r}[{row_flow.get('ingressInterface')!r}] "
            "is not the requested start location"
        )
    return True, None


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


def _freeze_value(value: object) -> object:
    """Hashable canonical form for Flow-identity grouping (N-02).

    Sort keys by repr so mixed-type keys can never break the ordering.
    Unrecognized leaves fall back to repr: grouping stays conservative
    (distinct instances) rather than crashing.
    """
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: repr(kv[0]))
        return tuple((key, _freeze_value(val)) for key, val in items)
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_value(v) for v in value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return repr(value)


def _side_row_ok(traces: object, count: object) -> tuple[bool, set[Reachability]]:
    """One side of one row: fully returned, unanimous, and known.

    Returns (ok, mapped_reaches). Mixed raw DENIED_* dispositions that map
    to one reachability are unanimous (N-01); nothing is inferred beyond
    the row's own traces and its own reported count.
    """
    total = _cell_count(count)
    if not isinstance(traces, list) or total is None:
        return False, set()
    returned = [_cell_dict(t) for t in traces]
    if len(returned) != total or not returned:
        return False, set()
    disps = [_cell_str(t.get("disposition")) for t in returned]
    reaches = {_batfish_reachability(d) for d in disps}
    if len(reaches) != 1 or "UNKNOWN" in reaches:
        return False, set()
    return True, set(reaches)


@dataclass(frozen=True)
class _DifferentialRowVerdict:
    """Row-level validation of one matched differential row (N-02-B).

    Each row carries its own trace collections and its own reported
    counts; validation never borrows traces or totals from another row.
    """

    complete: bool
    snapshot_ok: bool
    reference_ok: bool
    snapshot_reach: Reachability | None
    reference_reach: Reachability | None
    snapshot_returned: int = 0
    reference_returned: int = 0
    snapshot_reported: int | None = None
    reference_reported: int | None = None
    reason: str | None = None


def _validate_differential_row(row: dict) -> _DifferentialRowVerdict:
    """Validate one matched row independently against its own counts."""
    snap_traces = row.get("Snapshot_Traces")
    ref_traces = row.get("Reference_Traces")
    snap_count = _cell_count(row.get("Snapshot_TraceCount"))
    ref_count = _cell_count(row.get("Reference_TraceCount"))
    snap_returned = len(snap_traces) if isinstance(snap_traces, list) else 0
    ref_returned = len(ref_traces) if isinstance(ref_traces, list) else 0
    partial = {
        "snapshot_returned": snap_returned,
        "reference_returned": ref_returned,
        "snapshot_reported": snap_count,
        "reference_reported": ref_count,
    }
    if not isinstance(snap_traces, list) or not isinstance(ref_traces, list):
        return _DifferentialRowVerdict(
            complete=False,
            snapshot_ok=False,
            reference_ok=False,
            snapshot_reach=None,
            reference_reach=None,
            reason="trace count uncertain: non-list trace collection",
            **partial,  # type: ignore[arg-type]
        )
    if snap_count is None or ref_count is None:
        return _DifferentialRowVerdict(
            complete=False,
            snapshot_ok=False,
            reference_ok=False,
            snapshot_reach=None,
            reference_reach=None,
            reason="trace count uncertain: missing or invalid reported count",
            **partial,  # type: ignore[arg-type]
        )
    snap_ok, snap_reaches = _side_row_ok(snap_traces, snap_count)
    ref_ok, ref_reaches = _side_row_ok(ref_traces, ref_count)
    if snap_ok and ref_ok:
        return _DifferentialRowVerdict(
            complete=True,
            snapshot_ok=True,
            reference_ok=True,
            snapshot_reach=next(iter(snap_reaches)),
            reference_reach=next(iter(ref_reaches)),
            reason=None,
            **partial,  # type: ignore[arg-type]
        )
    if snap_returned != snap_count or ref_returned != ref_count:
        reason = (
            "trace truncation: snapshot returned "
            f"{snap_returned} of reported {snap_count}; reference returned "
            f"{ref_returned} of reported {ref_count}"
        )
    elif not snap_traces or not ref_traces:
        reason = "matched row returned no traces"
    else:
        observed = {
            _batfish_reachability(_cell_str(_cell_dict(t).get("disposition")))
            for t in [*snap_traces, *ref_traces]
        }
        if "UNKNOWN" in observed:
            reason = "trace dispositions include an unknown result"
        else:
            reason = "trace dispositions conflict within one Flow row"
    return _DifferentialRowVerdict(
        complete=False,
        snapshot_ok=snap_ok,
        reference_ok=ref_ok,
        snapshot_reach=None,
        reference_reach=None,
        reason=reason,
        **partial,  # type: ignore[arg-type]
    )


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
    matched_rows: list[dict] = []
    out_of_scope: list[dict] = []
    for row in rows:
        if not isinstance(row, dict):
            out_of_scope.append({"flow": None, "reason": "row is not a mapping"})
            continue
        ok, reason = _match_flow(flow, row.get("Flow"))
        if ok:
            matched_rows.append(row)
        else:
            out_of_scope.append({"flow": row.get("Flow"), "reason": reason})
    traces: list = []
    trace_complete = True
    for row in matched_rows:
        row_traces = _cell_list(row, "Traces")
        count = _cell_count(row.get("TraceCount"))
        if count is None or len(row_traces) != count:
            trace_complete = False
        traces.extend(row_traces)
    raw_disps = {_cell_str(_cell_dict(t).get("disposition")) for t in traces}
    reaches = {_batfish_reachability(d) for d in raw_disps}
    unanimous = bool(traces) and trace_complete and len(reaches) == 1 and "UNKNOWN" not in reaches
    raw_list = sorted(d for d in raw_disps if d is not None)
    common_details = {
        "matched_row_count": len(matched_rows),
        "out_of_scope_rows": out_of_scope,
        "trace_total": len(traces),
        "trace_complete": trace_complete and bool(traces),
        "traces": traces,
        # N-01: every raw disposition is preserved; the normalized result
        # lives in "reachability" and never invents a representative raw value.
        "raw_dispositions": raw_list,
    }
    if unanimous:
        reachability = next(iter(reaches))
        disposition = next(iter(raw_disps)) if len(raw_disps) == 1 else None
        outcome = IntentOutcome(reachability=reachability, batfish_disposition=disposition)
        summary = (
            f"{reachability} ({disposition})"
            if disposition is not None
            else f"{reachability} (mixed raw: {', '.join(raw_list)})"
        )
        result = _mint(
            store,
            tool="check_intent",
            snapshots=[snapshot.name],
            flow_id=flow.flow_id,
            status="ok",
            summary=summary,
            details={
                "batfish_disposition": disposition,
                "reachability": reachability,
                **common_details,
            },
            disposition=disposition,
        )
        return result, outcome
    if not matched_rows:
        reason = "no trace returned for the requested flow"
    elif not traces:
        reason = "matched rows returned no traces"
    elif not trace_complete:
        reason = "trace evidence incomplete: returned traces do not match reported counts"
    elif "UNKNOWN" in reaches or None in raw_disps:
        reason = "trace dispositions include an unknown result"
    else:
        reason = "trace dispositions conflict across returned traces"
    result = _mint(
        store,
        tool="check_intent",
        snapshots=[snapshot.name],
        flow_id=flow.flow_id,
        status="inconclusive",
        summary=f"UNKNOWN: {reason}",
        details={"error": reason, **common_details},
    )
    return result, IntentOutcome(reachability="UNKNOWN", batfish_disposition=None)


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
    matched_rows: list[dict] = []
    out_of_scope: list[dict] = []
    for row in rows:
        if not isinstance(row, dict):
            out_of_scope.append({"flow": None, "reason": "row is not a mapping"})
            continue
        ok, reason = _match_flow(flow, row.get("Flow"))
        if ok:
            matched_rows.append(row)
        else:
            out_of_scope.append({"flow": row.get("Flow"), "reason": reason})
    if not matched_rows:
        if out_of_scope:
            # F-01: rows exist but none match the declared flow. The flow's
            # change cannot be corroborated, and an unmatched row must never
            # stand in for it: inconclusive, never "not reported changed".
            result = _mint(
                store,
                tool="compare_snapshots",
                snapshots=[baseline.name, proposed.name],
                flow_id=flow.flow_id,
                status="inconclusive",
                summary=(
                    "differential inconclusive: rows present but none match "
                    f"the declared flow ({len(out_of_scope)} out-of-scope "
                    "row(s) recorded, never used)"
                ),
                details={
                    "reported_changed": False,
                    "matched_row_count": 0,
                    "out_of_scope_rows": out_of_scope,
                    "rows": rows,
                },
                disposition=None,
            )
            return result, DifferentialOutcome(
                False,
                None,
                None,
                0,
                0,
                query_ok=True,
                conclusive=False,
                incomplete_reason=(
                    "differential rows present but none match the declared flow"
                ),
                out_of_scope=tuple(out_of_scope),
            )
        result = _mint(
            store,
            tool="compare_snapshots",
            snapshots=[baseline.name, proposed.name],
            flow_id=flow.flow_id,
            status="ok",
            summary="not reported changed (absent row proves nothing)",
            details={
                "reported_changed": False,
                "matched_row_count": 0,
                "out_of_scope_rows": out_of_scope,
                "rows": rows,
            },
            disposition="NOT_REPORTED",
        )
        return result, DifferentialOutcome(
            False,
            None,
            None,
            0,
            0,
            query_ok=True,
            conclusive=True,
            out_of_scope=tuple(out_of_scope),
        )
    # N-02-C/D: group matched rows by concrete Flow identity. Rows that
    # differ only in the ephemeral source port are separate concrete
    # instances of the same FlowSpec; exact duplicate rows (identity,
    # traces, counts) are deduplicated. The same concrete Flow carrying
    # differing row evidence is never merged.
    instances: dict[object, list[dict]] = {}
    for row in matched_rows:
        instances.setdefault(_freeze_value(row.get("Flow")), []).append(row)
    distinct_rows: list[dict] = []
    for group in instances.values():
        seen: set[object] = set()
        unique: list[dict] = []
        for row in group:
            signature = (
                _freeze_value(row.get("Snapshot_Traces")),
                _freeze_value(row.get("Reference_Traces")),
                _cell_count(row.get("Snapshot_TraceCount")),
                _cell_count(row.get("Reference_TraceCount")),
            )
            if signature in seen:
                continue
            seen.add(signature)
            unique.append(row)
        if len(unique) > 1:
            reason = (
                "same Flow identity with conflicting row evidence; "
                "traces not merged and counts not added"
            )
            result = _mint(
                store,
                tool="compare_snapshots",
                snapshots=[baseline.name, proposed.name],
                flow_id=flow.flow_id,
                status="inconclusive",
                summary=f"differential ambiguous: {reason}",
                details={
                    "reported_changed": True,
                    "snapshot_trace_total": 0,
                    "reference_trace_total": 0,
                    "snapshot_complete": False,
                    "reference_complete": False,
                    "incomplete_reason": reason,
                    "matched_row_count": len(matched_rows),
                    "distinct_instance_count": 1,
                    "out_of_scope_rows": out_of_scope,
                    "rows": rows,
                },
                disposition="AMBIGUOUS",
            )
            return result, DifferentialOutcome(
                True,
                None,
                None,
                0,
                0,
                query_ok=True,
                conclusive=False,
                incomplete_reason=reason,
                out_of_scope=tuple(out_of_scope),
            )
        distinct_rows.append(unique[0])

    # N-02-B/E: validate each distinct instance against its own counts,
    # then aggregate only across complete instances. Totals below are
    # descriptive sums over validated distinct rows; completeness was
    # decided per row above and is never inferred from these sums.
    row_entries = [(row, _validate_differential_row(row)) for row in distinct_rows]
    snapshot_disps: list[str | None] = []
    reference_disps: list[str | None] = []
    for row in distinct_rows:
        for trace in _cell_list(row, "Snapshot_Traces"):
            snapshot_disps.append(_cell_str(_cell_dict(trace).get("disposition")))
        for trace in _cell_list(row, "Reference_Traces"):
            reference_disps.append(_cell_str(_cell_dict(trace).get("disposition")))
    snap_returned = sum(len(_cell_list(r, "Snapshot_Traces")) for r in distinct_rows)
    ref_returned = sum(len(_cell_list(r, "Reference_Traces")) for r in distinct_rows)
    snap_reported_values = {_cell_count(r.get("Snapshot_TraceCount")) for r in distinct_rows}
    ref_reported_values = {_cell_count(r.get("Reference_TraceCount")) for r in distinct_rows}
    snap_reported = next(iter(snap_reported_values)) if len(snap_reported_values) == 1 else None
    ref_reported = next(iter(ref_reported_values)) if len(ref_reported_values) == 1 else None
    snapshot_complete = all(v.snapshot_ok for _, v in row_entries)
    reference_complete = all(v.reference_ok for _, v in row_entries)
    row_verdicts = [
        {
            "flow": row.get("Flow"),
            "complete": v.complete,
            "snapshot_reach": v.snapshot_reach,
            "reference_reach": v.reference_reach,
            "reason": v.reason,
        }
        for row, v in row_entries
    ]
    common = {
        "reported_changed": True,
        "snapshot_dispositions": snapshot_disps,
        "reference_dispositions": reference_disps,
        "snapshot_trace_total": snap_returned,
        "reference_trace_total": ref_returned,
        "snapshot_reported_total": snap_reported,
        "reference_reported_total": ref_reported,
        "snapshot_complete": snapshot_complete,
        "reference_complete": reference_complete,
        "row_verdicts": row_verdicts,
        "matched_row_count": len(matched_rows),
        "distinct_instance_count": len(distinct_rows),
        "out_of_scope_rows": out_of_scope,
        "rows": rows,
    }
    incomplete = [(row, v) for row, v in row_entries if not v.complete]
    if incomplete:
        # N-02-E: any incomplete matching instance poisons the outcome;
        # complete out-of-scope rows can never rescue it.
        reasons = "; ".join(
            dict.fromkeys(v.reason for _, v in incomplete if v.reason)
        )
        reason = f"matching Flow instance incomplete: {reasons}"
        ambiguous = any(
            "conflict" in (v.reason or "") or "unknown result" in (v.reason or "")
            for _, v in incomplete
        )
        truncated = any("truncation" in (v.reason or "") for _, v in incomplete)
        disposition = (
            "AMBIGUOUS"
            if ambiguous
            else ("TRUNCATED" if truncated else "COUNT_UNCERTAIN")
        )
        result = _mint(
            store,
            tool="compare_snapshots",
            snapshots=[baseline.name, proposed.name],
            flow_id=flow.flow_id,
            status="inconclusive",
            summary=f"differential inconclusive: {reason}",
            details={**common, "incomplete_reason": reason},
            disposition=disposition,
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
            out_of_scope=tuple(out_of_scope),
        )
    snapshot_reaches = {v.snapshot_reach for _, v in row_entries}
    reference_reaches = {v.reference_reach for _, v in row_entries}
    if len(snapshot_reaches) != 1 or len(reference_reaches) != 1:
        reason = "conflicting reachability results across Flow instances"
        result = _mint(
            store,
            tool="compare_snapshots",
            snapshots=[baseline.name, proposed.name],
            flow_id=flow.flow_id,
            status="inconclusive",
            summary=f"differential ambiguous: {reason}",
            details={**common, "incomplete_reason": reason},
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
            incomplete_reason=reason,
            out_of_scope=tuple(out_of_scope),
        )
    snapshot_reach = next(iter(snapshot_reaches))
    reference_reach = next(iter(reference_reaches))
    assert snapshot_reach is not None and reference_reach is not None
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
        out_of_scope=tuple(out_of_scope),
    )
    out_note = (
        f"; {len(out_of_scope)} out-of-scope row(s) recorded, never used"
        if out_of_scope
        else ""
    )
    result = _mint(
        store,
        tool="compare_snapshots",
        snapshots=[baseline.name, proposed.name],
        flow_id=flow.flow_id,
        status="ok",
        summary=f"reported changed: {reference_reach} -> {snapshot_reach}{out_note}",
        details=common,
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
    matched_rows: list[dict] = []
    out_of_scope: list[dict] = []
    for row in rows:
        if not isinstance(row, dict):
            out_of_scope.append({"flow": None, "reason": "row is not a mapping"})
            continue
        ok, reason = _match_flow(flow, row.get("Flow"))
        if ok:
            matched_rows.append(row)
        else:
            out_of_scope.append({"flow": row.get("Flow"), "reason": reason})
    traces: list = []
    trace_complete = True
    for row in matched_rows:
        row_traces = _cell_list(row, "Traces")
        count = _cell_count(row.get("TraceCount"))
        if count is None or len(row_traces) != count:
            trace_complete = False
        traces.extend(_cell_dict(t) for t in row_traces)
    raw_disps = {_cell_str(t.get("disposition")) for t in traces}
    reaches = {_batfish_reachability(d) for d in raw_disps}
    unanimous = bool(traces) and trace_complete and len(reaches) == 1 and "UNKNOWN" not in reaches
    # N-01: completeness is a reachability-level property. Mixed raw DENIED_*
    # dispositions that map to one reachability are unanimous; no single raw
    # value is invented to represent the group.
    final = next(iter(raw_disps)) if unanimous and len(raw_disps) == 1 else None
    final_reach = next(iter(reaches)) if unanimous else None
    raw_list = sorted(d for d in raw_disps if d is not None)
    acl_matches: list[dict] = []
    if traces:
        for trace in traces:
            for hop in _cell_list(trace, "hops"):
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
    complete = unanimous
    if not matched_rows:
        summary = "trace incomplete: no trace returned for the requested flow"
    elif not complete:
        summary = "trace incomplete: partial or conflicting trace evidence"
    elif final is not None:
        summary = f"final disposition {final}"
    else:
        summary = f"final reachability {final_reach} (mixed raw: {', '.join(raw_list)})"
    if out_of_scope:
        summary += f"; {len(out_of_scope)} out-of-scope row(s) recorded, never used"
    return _mint(
        store,
        tool="trace_flow",
        snapshots=[snapshot.name],
        flow_id=flow.flow_id,
        status="ok" if complete else "inconclusive",
        summary=summary,
        details={
            "final_disposition": final,
            "reachability": final_reach,
            "raw_dispositions": raw_list,
            "traces": traces,
            "trace_complete": complete,
            "matched_row_count": len(matched_rows),
            "out_of_scope_rows": out_of_scope,
            "acl_matches": acl_matches,
        },
        disposition=final,
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
            "candidates": [],
            "unparseable_rows": [],
        }
    config_rules: tuple = ()
    config_error: str | None = None
    try:
        config_rules = load_node_acl(snapshot_path, node, filter_name)
    except AclParseError as exc:
        config_error = str(exc)
    matches = []
    unparseable = []
    for row in rows:
        row_record = _cell_dict(row)
        content = _cell_str(row_record.get("Line_Content"))
        if content is None:
            unparseable.append(
                {
                    "matched_line_content": row_record.get("Line_Content"),
                    "action": row_record.get("Action"),
                    "parse_error": "missing or non-string Line_Content",
                }
            )
            continue
        try:
            parsed = parse_acl_rule_line(content)
        except AclParseError as exc:
            unparseable.append(
                {
                    "matched_line_content": content,
                    "action": row_record.get("Action"),
                    "parse_error": str(exc),
                }
            )
            continue
        sequence: int | None = None
        source: str | None = None
        if config_error is None:
            hits = [r.sequence_number for r in config_rules if r.rule == parsed.rule]
            if len(hits) == 1:
                sequence, source = hits[0], "config-parser"
        matches.append(
            {
                "node": node,
                "filter": filter_name,
                "action": row_record.get("Action"),
                "matched_line_content": content,
                "batfish_line_index": None,
                "sequence_number": sequence,
                "sequence_source": source,
                "parser_error": config_error,
            }
        )
    base = {
        "node": node,
        "filter": filter_name,
        "candidates": matches,
        "unparseable_rows": unparseable,
    }
    if unparseable and not matches:
        return {
            **base,
            "resolution": "unresolved",
            "reason": (
                f"{len(unparseable)} testFilters row(s) could not be parsed; "
                "attribution incomplete"
            ),
        }
    if unparseable and matches:
        for match in matches:
            match["resolution"] = "incomplete"
        return {
            **base,
            "resolution": "incomplete",
            "reason": (
                f"{len(unparseable)} potentially relevant row(s) could not be parsed; "
                "attribution incomplete and must not be used for patching"
            ),
        }
    if not matches:
        return {
            **base,
            "resolution": "unresolved",
            "reason": "testFilters named the filter but no rule line reconciled",
        }
    if len(matches) > 1:
        for match in matches:
            match["resolution"] = "ambiguous"
        return {
            **base,
            "resolution": "ambiguous",
            "reason": "multiple candidate rules; refusing to guess",
        }
    matches[0]["resolution"] = (
        "unique-match" if matches[0]["sequence_number"] is not None else "unresolved"
    )
    return {**base, **matches[0], "reason": None}


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
            details={
                "node": node,
                "prefix": network,
                "route_found": True,
                "route_count": len(rows),
                "routes": rows,
            },
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
            "prefix": network,
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
