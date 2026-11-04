"""Stage C verification: independently prove a candidate repairs intent.

Read-only. The caller supplies an already-initialized candidate snapshot,
the immutable Stage A result, and the shared run EvidenceStore. Nothing
here applies operations, creates directories, initializes or deletes
snapshots, assembles reports, or calls any model: every conclusion comes
from the existing deterministic tools plus Stage A truth tables.

Outcome contract: VERIFIED only when every required check passes;
UNVERIFIABLE takes precedence over REJECTED whenever any required check
is UNKNOWN.
"""

from __future__ import annotations

from netops_lens.assessment import differential_consistency, reconcile_flow
from netops_lens.batfish_client import BatfishClient, is_candidate_snapshot_name
from netops_lens.evidence import EvidenceStore
from netops_lens.models import (
    AssessmentResult,
    CandidateId,
    CheckOutcome,
    FlowKind,
    FlowSpec,
    Intent,
    Reachability,
    SnapshotHealth,
    SnapshotRef,
    VerificationCheck,
    VerificationResult,
    VerificationStatus,
)
from netops_lens.tools import (
    DifferentialOutcome,
    IntentOutcome,
    check_intent,
    compare_snapshots,
    get_snapshot_health,
)


def _check(
    name: str,
    outcome: CheckOutcome,
    detail: str,
    evidence_ids: tuple[str, ...] = (),
) -> VerificationCheck:
    return VerificationCheck(
        name=name,
        outcome=outcome,
        detail=detail,
        evidence_ids=evidence_ids,
    )


def _decide(checks: list[VerificationCheck]) -> VerificationStatus:
    if not checks:
        return "UNVERIFIABLE"
    outcomes = [check.outcome for check in checks]
    if "unknown" in outcomes:
        return "UNVERIFIABLE"
    if "fail" in outcomes:
        return "REJECTED"
    return "VERIFIED"


def _assemble(
    candidate_id: str,
    candidate_snapshot: str | None,
    checks: list[VerificationCheck],
    reasons: list[str],
) -> VerificationResult:
    """Build the immutable result; result evidence is the ordered dedup union."""
    ordered: list[str] = []
    for check in checks:
        for evidence_id in check.evidence_ids:
            if evidence_id not in ordered:
                ordered.append(evidence_id)
    return VerificationResult(
        candidate_id=candidate_id,
        status=_decide(checks),
        reasons=tuple(dict.fromkeys(reasons)),
        checks=tuple(checks),
        evidence_ids=tuple(ordered),
        candidate_snapshot=candidate_snapshot,
    )


def _reference_health(
    stage_a: AssessmentResult, baseline_name: str
) -> tuple[SnapshotHealth | None, str | None]:
    """Baseline health by snapshot name; (health, reason_if_unusable)."""
    matches = [h for h in stage_a.health if h.snapshot == baseline_name]
    if not matches:
        return None, f"baseline snapshot '{baseline_name}' has no health record in Stage A"
    if len(matches) > 1:
        return (
            None,
            f"baseline snapshot '{baseline_name}' has ambiguous health records in Stage A",
        )
    health = matches[0]
    if health.status != "OK":
        joined = "; ".join(health.reasons) if health.reasons else "no reason recorded"
        return None, f"baseline snapshot '{baseline_name}' health is NOT_OK: {joined}"
    return health, None


def _reference_comparisons(
    stage_a: AssessmentResult, flows: list[tuple[FlowKind, FlowSpec]]
) -> tuple[dict[str, tuple[FlowKind, Reachability]], dict[str, str]]:
    """Baseline reachability per flow from Stage A comparisons.

    Returns (reach_by_flow_id, problem_by_flow_id). Missing, duplicated,
    kind-mismatched, or UNKNOWN baseline records are problems, never
    treated as known results.
    """
    by_id: dict[str, list] = {}
    for comparison in stage_a.flow_comparisons:
        by_id.setdefault(comparison.flow_id, []).append(comparison)
    reach: dict[str, tuple[FlowKind, Reachability]] = {}
    problems: dict[str, str] = {}
    for kind, flow in flows:
        matches = by_id.get(flow.flow_id, [])
        if len(matches) != 1:
            problems[flow.flow_id] = (
                f"flow '{flow.flow_id}' has {len(matches)} usable Stage A "
                "comparisons; need exactly one"
            )
            continue
        comparison = matches[0]
        if comparison.kind != kind:
            problems[flow.flow_id] = (
                f"flow '{flow.flow_id}' Stage A kind '{comparison.kind}' "
                f"does not match intent '{kind}'"
            )
            continue
        if comparison.baseline_reach == "UNKNOWN":
            problems[flow.flow_id] = (
                f"flow '{flow.flow_id}' baseline reachability is UNKNOWN in Stage A"
            )
            continue
        reach[flow.flow_id] = (kind, comparison.baseline_reach)
    return reach, problems


def _required_reach(kind: FlowKind) -> Reachability:
    return "REACHABLE" if kind == "must_reach" else "UNREACHABLE"


def _declared_flows(intent: Intent) -> list[tuple[FlowKind, FlowSpec]]:
    return [("must_reach", f) for f in intent.must_reach] + [
        ("must_not_reach", f) for f in intent.must_not_reach
    ]


def empty_skeleton(
    candidate_id: str,
    candidate_snapshot: str | None,
    intent: Intent,
    reason: str,
    health_evidence: tuple[str, ...] = (),
) -> VerificationResult:
    """Full UNKNOWN check skeleton for prerequisites that never executed.

    Every known intent flow gets ``intent:``, ``differential:`` and
    ``no_regression:`` checks marked UNKNOWN with no evidence attached;
    nothing is fabricated. Used for invalid snapshot identity, unusable
    baseline references, unhealthy candidates, and snapshot-initialization
    failures. ``candidate_snapshot`` is None when no candidate snapshot
    was ever successfully created. ``health_evidence`` carries the real
    minted health evidence ID when a candidate-health query actually ran;
    every other unevaluated check keeps empty evidence.
    """
    prefixed = f"not executed: {reason}"
    checks = [_check("candidate_health", "unknown", prefixed, health_evidence)]
    for _, flow in _declared_flows(intent):
        checks.append(_check(f"intent:{flow.flow_id}", "unknown", prefixed))
        checks.append(_check(f"differential:{flow.flow_id}", "unknown", prefixed))
        checks.append(_check(f"no_regression:{flow.flow_id}", "unknown", prefixed))
    return _assemble(candidate_id, candidate_snapshot, checks, [c.detail for c in checks])


def verify_candidate(
    client: BatfishClient,
    store: EvidenceStore,
    *,
    candidate_id: CandidateId,
    baseline_ref: SnapshotRef,
    candidate_ref: SnapshotRef,
    intent: Intent,
    stage_a: AssessmentResult,
) -> VerificationResult:
    """Verify one applied candidate against baseline using fresh evidence.

    Every declared intent flow is checked on the candidate snapshot
    (``check_intent``), cross-checked baseline-vs-candidate
    (``compare_snapshots`` with the baseline as reference), and reconciled
    with the shared Stage A consistency helper and truth tables. Baseline
    reachability and health come from ``stage_a`` alone, never recomputed.
    """
    candidate_name = candidate_ref.name
    # LOW-1 identity guard: never verify a baseline snapshot against
    # itself, and never accept a non-canonical candidate name. This runs
    # before any verification tool call.
    if candidate_name == baseline_ref.name:
        return empty_skeleton(
            candidate_id,
            None,
            intent,
            f"candidate snapshot '{candidate_name}' equals the baseline snapshot",
        )
    if not is_candidate_snapshot_name(candidate_name):
        return empty_skeleton(
            candidate_id,
            None,
            intent,
            f"candidate snapshot '{candidate_name}' is not a canonical generated name",
        )
    flows = _declared_flows(intent)
    if not flows:
        return _assemble(
            candidate_id,
            candidate_name,
            [],
            ["no declared intent flows to verify"],
        )

    # Step 1 — validate the Stage A reference (read-only, by name, never position).
    _, health_problem = _reference_health(stage_a, baseline_ref.name)
    baseline_reach, problems = _reference_comparisons(stage_a, flows)
    if health_problem is not None or problems:
        parts = ([health_problem] if health_problem is not None else []) + [
            problems[flow.flow_id] for _, flow in flows if flow.flow_id in problems
        ]
        return empty_skeleton(
            candidate_id,
            candidate_name,
            intent,
            f"baseline reference unusable: {'; '.join(parts)}",
        )

    # Step 2 — candidate snapshot health (no flow checks on an unhealthy snapshot).
    try:
        health_result, cand_health = get_snapshot_health(client, store, candidate_ref)
        health_evidence: tuple[str, ...] = (health_result.evidence_id,)
        health_error: Exception | None = None
    except Exception as exc:
        health_evidence, health_error = (), exc
        cand_health = None
    if health_error is not None:
        return empty_skeleton(
            candidate_id,
            candidate_name,
            intent,
            f"candidate health query raised {type(health_error).__name__}",
        )
    if cand_health is None:  # defensive; try/except above prevents this
        return empty_skeleton(
            candidate_id, candidate_name, intent, "candidate health result missing"
        )
    if cand_health.status != "OK":
        joined = "; ".join(cand_health.reasons) if cand_health.reasons else "no reason recorded"
        return empty_skeleton(
            candidate_id,
            candidate_name,
            intent,
            f"candidate snapshot '{candidate_name}' health is {cand_health.status}: {joined}",
            health_evidence,
        )
    checks = [
        _check(
            "candidate_health",
            "pass",
            f"candidate snapshot '{candidate_name}' health OK",
            health_evidence,
        )
    ]

    # Steps 3-5 — every declared flow: direct check, differential, reconcile.
    for kind, flow in flows:
        try:
            direct_result, direct_outcome = check_intent(client, store, flow, candidate_ref)
            direct_evidence: tuple[str, ...] = (direct_result.evidence_id,)
            direct_error: Exception | None = None
        except Exception as exc:
            direct_evidence = ()
            direct_error = exc
            direct_outcome = IntentOutcome(reachability="UNKNOWN", batfish_disposition=None)
        cand_reach = direct_outcome.reachability
        if direct_error is not None:
            checks.append(
                _check(
                    f"intent:{flow.flow_id}",
                    "unknown",
                    f"candidate intent check raised {type(direct_error).__name__}",
                )
            )
        elif cand_reach == "UNKNOWN":
            checks.append(
                _check(
                    f"intent:{flow.flow_id}",
                    "unknown",
                    f"candidate reachability UNKNOWN for flow '{flow.flow_id}'",
                    direct_evidence,
                )
            )
        elif cand_reach == _required_reach(kind):
            checks.append(
                _check(
                    f"intent:{flow.flow_id}",
                    "pass",
                    f"candidate {cand_reach} satisfies {kind} for flow '{flow.flow_id}'",
                    direct_evidence,
                )
            )
        else:
            checks.append(
                _check(
                    f"intent:{flow.flow_id}",
                    "fail",
                    f"candidate {cand_reach} violates {kind} for flow '{flow.flow_id}'",
                    direct_evidence,
                )
            )

        try:
            diff_result, diff_outcome = compare_snapshots(
                client, store, flow, baseline_ref, candidate_ref
            )
            diff_evidence: tuple[str, ...] = (diff_result.evidence_id,)
        except Exception:
            diff_evidence = ()
            diff_outcome = DifferentialOutcome(
                reported_changed=False,
                snapshot_reach=None,
                reference_reach=None,
                snapshot_trace_total=0,
                reference_trace_total=0,
                query_ok=False,
                conclusive=False,
            )
        if diff_outcome.query_ok and diff_outcome.conclusive:
            checks.append(
                _check(
                    f"differential:{flow.flow_id}",
                    "pass",
                    f"differential baseline-vs-candidate complete for flow '{flow.flow_id}'",
                    diff_evidence,
                )
            )
        else:
            reason = diff_outcome.incomplete_reason or "differential evidence unavailable"
            checks.append(
                _check(
                    f"differential:{flow.flow_id}",
                    "unknown",
                    f"differential incomplete for flow '{flow.flow_id}': {reason}",
                    diff_evidence,
                )
            )

        base_reach = baseline_reach[flow.flow_id][1]
        inputs = differential_consistency(base_reach, cand_reach, diff_outcome)
        classification, discrepancy = reconcile_flow(
            kind,
            base_reach,
            cand_reach,
            reported_changed=inputs.reported_changed,
            consistent=inputs.consistent,
            diff_ok=inputs.diff_ok,
            ambiguous=inputs.ambiguous,
            ambiguous_detail=inputs.ambiguous_detail,
        )
        no_reg_evidence = direct_evidence + diff_evidence
        if classification in ("NO_CHANGE_OK", "IMPROVEMENT"):
            checks.append(
                _check(
                    f"no_regression:{flow.flow_id}",
                    "pass",
                    f"no regression for flow '{flow.flow_id}': "
                    f"{base_reach} -> {cand_reach} ({classification})",
                    no_reg_evidence,
                )
            )
        elif classification == "REGRESSION":
            checks.append(
                _check(
                    f"no_regression:{flow.flow_id}",
                    "fail",
                    f"regression for flow '{flow.flow_id}': {base_reach} -> {cand_reach}",
                    no_reg_evidence,
                )
            )
        elif classification == "PRE_EXISTING_VIOLATION":
            # Definite and completely evidenced, but not an allowed success:
            # the intent requirement still fails, so this is conclusive
            # non-acceptance (REJECTED), never an inconclusive UNKNOWN.
            checks.append(
                _check(
                    f"no_regression:{flow.flow_id}",
                    "fail",
                    f"pre-existing violation persists for flow '{flow.flow_id}': "
                    f"{base_reach} -> {cand_reach} (PRE_EXISTING_VIOLATION)",
                    no_reg_evidence,
                )
            )
        else:
            note = f": {discrepancy}" if discrepancy else ""
            checks.append(
                _check(
                    f"no_regression:{flow.flow_id}",
                    "unknown",
                    f"reconciliation inconclusive for flow '{flow.flow_id}'{note}",
                    no_reg_evidence,
                )
            )

    reasons = [check.detail for check in checks if check.outcome != "pass"]
    return _assemble(candidate_id, candidate_name, checks, reasons)
