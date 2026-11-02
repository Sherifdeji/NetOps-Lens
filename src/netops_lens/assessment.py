"""Stage A: mandatory deterministic assessment. No LLM code is imported here.

``run_mandatory_assessment`` executes the fixed contract in order — health on
both snapshots, ``check_intent`` for every declared flow on both snapshots,
``compare_snapshots`` for every declared flow — with no skip, reorder, or
early-exit hook. The verdict is computed by Python alone.
"""

from __future__ import annotations

from collections.abc import Sequence

from netops_lens.batfish_client import BatfishClient
from netops_lens.evidence import EvidenceStore, validate_finding
from netops_lens.models import (
    AssessmentResult,
    ClaimType,
    Finding,
    FlowClassification,
    FlowComparison,
    FlowKind,
    FlowSpec,
    Intent,
    Reachability,
    SnapshotRef,
    Verdict,
)
from netops_lens.tools import (
    check_intent,
    compare_snapshots,
    get_snapshot_health,
)


class AssessmentError(Exception):
    """An internal Stage A failure (never a verdict)."""


_GRID: dict[tuple[FlowKind, Reachability, Reachability], FlowClassification] = {
    ("must_reach", "REACHABLE", "REACHABLE"): "NO_CHANGE_OK",
    ("must_reach", "REACHABLE", "UNREACHABLE"): "REGRESSION",
    ("must_reach", "REACHABLE", "UNKNOWN"): "UNKNOWN",
    ("must_reach", "UNREACHABLE", "REACHABLE"): "IMPROVEMENT",
    ("must_reach", "UNREACHABLE", "UNREACHABLE"): "PRE_EXISTING_VIOLATION",
    ("must_reach", "UNREACHABLE", "UNKNOWN"): "UNKNOWN",
    ("must_reach", "UNKNOWN", "REACHABLE"): "UNKNOWN",
    ("must_reach", "UNKNOWN", "UNREACHABLE"): "UNKNOWN",
    ("must_reach", "UNKNOWN", "UNKNOWN"): "UNKNOWN",
    ("must_not_reach", "REACHABLE", "REACHABLE"): "PRE_EXISTING_VIOLATION",
    ("must_not_reach", "REACHABLE", "UNREACHABLE"): "IMPROVEMENT",
    ("must_not_reach", "REACHABLE", "UNKNOWN"): "UNKNOWN",
    ("must_not_reach", "UNREACHABLE", "REACHABLE"): "REGRESSION",
    ("must_not_reach", "UNREACHABLE", "UNREACHABLE"): "NO_CHANGE_OK",
    ("must_not_reach", "UNREACHABLE", "UNKNOWN"): "UNKNOWN",
    ("must_not_reach", "UNKNOWN", "REACHABLE"): "UNKNOWN",
    ("must_not_reach", "UNKNOWN", "UNREACHABLE"): "UNKNOWN",
    ("must_not_reach", "UNKNOWN", "UNKNOWN"): "UNKNOWN",
}


def classify_flow(
    kind: FlowKind, baseline_reach: Reachability, proposed_reach: Reachability
) -> FlowClassification:
    """Per-flow truth table from the implementation plan.

    The two clause tables share the UNKNOWN rows, but the diagonal cells
    differ by kind: satisfied-and-unchanged is NO_CHANGE_OK, while a
    prohibition that never held (or a requirement never met) is
    PRE_EXISTING_VIOLATION.
    """
    return _GRID[(kind, baseline_reach, proposed_reach)]


def reconcile_flow(
    kind: FlowKind,
    baseline_reach: Reachability,
    proposed_reach: Reachability,
    *,
    reported_changed: bool | None,
    consistent: bool,
    diff_ok: bool,
    ambiguous: bool = False,
    ambiguous_detail: str | None = None,
) -> tuple[FlowClassification, str | None]:
    """Reconcile direct dispositions with the differential cross-check.

    Returns (classification, discrepancy_note | None). A discrepancy note is
    only produced when the direct records themselves show a change, so a
    REACHABILITY_CHANGED finding built from them always validates.

    ``consistent`` compares mapped reachability states on both sides, never
    raw disposition strings: a differential row of NO_ROUTE vs DENIED_IN
    agrees with direct UNREACHABLE -> UNREACHABLE and is not a regression.
    """
    if not diff_ok:
        if ambiguous:
            return (
                "UNKNOWN",
                ambiguous_detail
                or "differential traces ambiguous or conflicting; cross-check incomplete",
            )
        return "UNKNOWN", "differential query failed; cross-check incomplete"
    if "UNKNOWN" in (baseline_reach, proposed_reach):
        return "UNKNOWN", None
    changed = baseline_reach != proposed_reach
    if changed and (not reported_changed or not consistent):
        return (
            "UNKNOWN",
            "direct checks indicate change, differential does not corroborate",
        )
    if not changed and reported_changed and not consistent:
        return "UNKNOWN", "differential reports change conflicting with direct results"
    return _GRID[(kind, baseline_reach, proposed_reach)], None


def decide_verdict(health_ok: bool, classifications: Sequence[FlowClassification]) -> Verdict:
    """Overall verdict by documented precedence (gate first, then presence)."""
    if not health_ok:
        return "INCONCLUSIVE"
    if "REGRESSION" in classifications:
        return "REGRESSION_DETECTED"
    if "UNKNOWN" in classifications:
        return "INCONCLUSIVE"
    if "PRE_EXISTING_VIOLATION" in classifications:
        return "INCONCLUSIVE"
    return "NO_REGRESSION_DETECTED"


def run_mandatory_assessment(
    client: BatfishClient,
    store: EvidenceStore,
    baseline: SnapshotRef,
    proposed: SnapshotRef,
    intent: Intent,
) -> AssessmentResult:
    """Execute Stage A in fixed order; return the immutable AssessmentResult."""
    allowed = {baseline.name, proposed.name}
    health_by_name = {}
    health_evidence: dict[str, str] = {}
    for ref in (baseline, proposed):
        health_result, health = get_snapshot_health(client, store, ref)
        health_by_name[ref.name] = health
        health_evidence[ref.name] = health_result.evidence_id
    health_ok = all(
        h.status == "OK" for h in (health_by_name[baseline.name], health_by_name[proposed.name])
    )

    flows: list[tuple[FlowKind, FlowSpec]] = [("must_reach", f) for f in intent.must_reach] + [
        ("must_not_reach", f) for f in intent.must_not_reach
    ]

    comparisons: list[FlowComparison] = []
    findings: list[Finding] = []
    inconclusive_reasons: list[str] = []
    finding_counter = 0

    def next_finding_id() -> str:
        nonlocal finding_counter
        finding_counter += 1
        return f"f-{finding_counter:04d}"

    def add_finding(
        *,
        claim_type: ClaimType,
        flow_id: str | None,
        statement: str,
        evidence_ids: list[str],
        severity: str,
        kind: FlowKind | None,
        subject_snapshot: str,
    ) -> None:
        finding = Finding(
            finding_id=next_finding_id(),  # type: ignore[arg-type]
            claim_type=claim_type,
            flow_id=flow_id,
            statement=statement,
            evidence_ids=tuple(evidence_ids),  # type: ignore[arg-type]
            severity=severity,
        )
        ok, failed = validate_finding(
            finding,
            store,
            allowed_snapshots=allowed,
            kind=kind,
            subject_snapshot=subject_snapshot,
        )
        if not ok:
            raise AssessmentError(f"generated finding failed validation ({failed}): {statement}")
        findings.append(finding)

    for ref in (baseline, proposed):
        health = health_by_name[ref.name]
        if health.status == "OK":
            add_finding(
                claim_type=ClaimType.SNAPSHOT_HEALTH,
                flow_id=None,
                statement=f"snapshot '{ref.name}' health OK",
                evidence_ids=[health_evidence[ref.name]],
                severity="info",
                kind=None,
                subject_snapshot=ref.name,
            )
        else:
            add_finding(
                claim_type=ClaimType.SNAPSHOT_HEALTH,
                flow_id=None,
                statement=f"snapshot '{ref.name}' health NOT_OK: {'; '.join(health.reasons)}",
                evidence_ids=[health_evidence[ref.name]],
                severity="error",
                kind=None,
                subject_snapshot=ref.name,
            )

    for kind, flow in flows:
        base_result, base_outcome = check_intent(client, store, flow, baseline)
        prop_result, prop_outcome = check_intent(client, store, flow, proposed)
        diff_result, diff_outcome = compare_snapshots(client, store, flow, baseline, proposed)
        base_reach = base_outcome.reachability
        prop_reach = prop_outcome.reachability
        cross_ok = diff_outcome.query_ok and diff_outcome.conclusive
        consistent = cross_ok and (
            (
                diff_outcome.reported_changed
                and diff_outcome.reference_reach == base_reach
                and diff_outcome.snapshot_reach == prop_reach
            )
            or not diff_outcome.reported_changed
        )
        classification, discrepancy = reconcile_flow(
            kind,
            base_reach,
            prop_reach,
            reported_changed=diff_outcome.reported_changed if cross_ok else None,
            consistent=consistent,
            diff_ok=cross_ok,
            ambiguous=diff_outcome.query_ok and not diff_outcome.conclusive,
            ambiguous_detail=diff_outcome.incomplete_reason,
        )
        comparisons.append(
            FlowComparison(
                flow_id=flow.flow_id,
                kind=kind,
                baseline_reach=base_reach,
                proposed_reach=prop_reach,
                classification=classification,
            )
        )
        flow_evidence = [base_result.evidence_id, prop_result.evidence_id]
        if discrepancy is not None and base_reach != prop_reach:
            add_finding(
                claim_type=ClaimType.REACHABILITY_CHANGED,
                flow_id=flow.flow_id,
                statement=(
                    f"flow '{flow.flow_id}' ({kind}): direct checks indicate "
                    f"{base_reach} -> {prop_reach} but {discrepancy}; treated as UNKNOWN"
                ),
                evidence_ids=[*flow_evidence, diff_result.evidence_id],
                severity="warning",
                kind=kind,
                subject_snapshot=proposed.name,
            )
        if "UNKNOWN" in (base_reach, prop_reach):
            inconclusive_reasons.append(
                f"flow '{flow.flow_id}' ({kind}) undecided: "
                f"baseline {base_reach}, proposed {prop_reach}"
            )
            continue
        if discrepancy is not None:
            inconclusive_reasons.append(f"flow '{flow.flow_id}' ({kind}): {discrepancy}")
            continue
        if classification == "NO_CHANGE_OK":
            add_finding(
                claim_type=ClaimType.INTENT_SATISFIED,
                flow_id=flow.flow_id,
                statement=(
                    f"flow '{flow.flow_id}' ({kind}) unchanged and satisfied: "
                    f"{base_reach} -> {prop_reach}"
                ),
                evidence_ids=flow_evidence,
                severity="info",
                kind=kind,
                subject_snapshot=proposed.name,
            )
        elif classification == "REGRESSION":
            add_finding(
                claim_type=ClaimType.INTENT_VIOLATED,
                flow_id=flow.flow_id,
                statement=(
                    f"flow '{flow.flow_id}' ({kind}) regressed: {base_reach} -> {prop_reach}"
                ),
                evidence_ids=flow_evidence,
                severity="error",
                kind=kind,
                subject_snapshot=proposed.name,
            )
        elif classification == "IMPROVEMENT":
            add_finding(
                claim_type=ClaimType.INTENT_SATISFIED,
                flow_id=flow.flow_id,
                statement=(
                    f"flow '{flow.flow_id}' ({kind}) improved: {base_reach} -> {prop_reach}"
                ),
                evidence_ids=flow_evidence,
                severity="info",
                kind=kind,
                subject_snapshot=proposed.name,
            )
        elif classification == "PRE_EXISTING_VIOLATION":
            add_finding(
                claim_type=ClaimType.INTENT_VIOLATED,
                flow_id=flow.flow_id,
                statement=(
                    f"flow '{flow.flow_id}' ({kind}) still violates intent in proposed "
                    f"(pre-existing; change did not cause it): {base_reach} -> {prop_reach}"
                ),
                evidence_ids=flow_evidence,
                severity="warning",
                kind=kind,
                subject_snapshot=proposed.name,
            )
            inconclusive_reasons.append(
                "pre-existing intent failure persists; no new regression on tested flows"
            )

    if not health_ok:
        for ref in (baseline, proposed):
            health = health_by_name[ref.name]
            if health.status == "NOT_OK":
                inconclusive_reasons.append(
                    f"snapshot '{ref.name}' health NOT_OK; flow analysis not trusted"
                )

    if len(comparisons) != len(flows):
        raise AssessmentError("completeness failure: a declared flow has no comparison")
    verdict = decide_verdict(health_ok, [c.classification for c in comparisons])
    return AssessmentResult(
        verdict=verdict,
        flow_comparisons=tuple(comparisons),
        findings=tuple(findings),
        inconclusive_reasons=tuple(inconclusive_reasons),
        health=(
            health_by_name[baseline.name],
            health_by_name[proposed.name],
        ),
    )
