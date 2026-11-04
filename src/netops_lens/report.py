"""Report assembly: assessment + investigation + Stage C, exactly once.

Stage A assessment, Stage B investigation, and Stage C application and
verification results are combined here with the shared run evidence index.
Findings are never generated from model text — only ``assessment.py``
writes them. The caller collects all human decisions before calling this;
the returned report is final and never mutated afterwards.
"""

from __future__ import annotations

from collections.abc import Collection, Mapping

from netops_lens.evidence import EvidenceStore
from netops_lens.models import (
    ApplicationResult,
    AssessmentResult,
    HumanDecision,
    InvestigationResult,
    Report,
    VerificationResult,
)


class ReportError(Exception):
    """A report that must not be rendered (e.g., incomplete assessment)."""


def assemble_report(
    assessment: AssessmentResult,
    store: EvidenceStore,
    *,
    expected_flow_ids: Collection[str],
    investigation: InvestigationResult | None = None,
    applications: Collection[ApplicationResult] = (),
    verifications: Collection[VerificationResult] = (),
    human_decision: Mapping[str, HumanDecision] | None = None,
) -> Report:
    """Assemble the final report; refuse inconsistent Stage C results loudly.

    ``investigation=None`` preserves the exact Phase 2 ``--no-investigate``
    shape. Stage C evidence lives in the same store, so it lands in the
    evidence index automatically. Application, verification, and decision
    records are associated by candidate ID: duplicates, mismatches, or
    decision gaps raise instead of rendering a partial report.
    """
    actual = [c.flow_id for c in assessment.flow_comparisons]
    if len(actual) != len(set(actual)) or set(actual) != set(expected_flow_ids):
        raise ReportError(
            "assessment coverage mismatch: "
            f"expected {sorted(expected_flow_ids)}, got {sorted(actual)}"
        )
    app_ids = [a.candidate_id for a in applications]
    ver_ids = [v.candidate_id for v in verifications]
    if len(set(app_ids)) != len(app_ids) or len(set(ver_ids)) != len(ver_ids):
        raise ReportError("duplicate candidate application or verification record")
    if set(app_ids) != set(ver_ids):
        raise ReportError(
            "candidate application/verification mismatch: "
            f"applications={sorted(app_ids)}, verifications={sorted(ver_ids)}"
        )
    decisions = dict(human_decision) if human_decision else {}
    if set(decisions) != set(app_ids):
        raise ReportError(
            "candidate human-decision mismatch: "
            f"decisions={sorted(decisions)}, applications={sorted(app_ids)}"
        )
    ver_by_id = {v.candidate_id: v for v in verifications}
    for candidate_id, decision in decisions.items():
        verification = ver_by_id[candidate_id]
        if decision == "APPROVED" and verification.status != "VERIFIED":
            raise ReportError(
                f"candidate {candidate_id} decision APPROVED is illegal "
                f"for verification status {verification.status}"
            )
    submitted = (
        {c.candidate_id for c in investigation.candidates}
        if investigation is not None
        else set()
    )
    # The coverage invariant binds only when submission was legitimate, i.e.
    # a REGRESSION_DETECTED verdict. Otherwise Stage C is correctly skipped
    # and the report legitimately carries no Stage C records; crashing the
    # assessment report over an impossible combination would lose real data.
    if assessment.verdict == "REGRESSION_DETECTED" and submitted != set(app_ids):
        raise ReportError(
            "submitted candidates without application results: "
            f"submitted={sorted(submitted)}, applications={sorted(app_ids)}"
        )
    evidence_index = {}
    for evidence_id in store.ids():
        record = store.get(evidence_id)
        if record is None:  # pragma: no cover - store is append-only
            raise ReportError(f"evidence {evidence_id} vanished from the store")
        evidence_index[evidence_id] = record
    for verification in verifications:
        for check in verification.checks:
            for evidence_id in check.evidence_ids:
                if evidence_id not in evidence_index:
                    raise ReportError(
                        f"verification {verification.candidate_id} references "
                        f"missing evidence {evidence_id}"
                    )
    return Report(
        assessment=assessment,
        investigation=investigation,
        applications=list(applications),
        verifications=list(verifications),
        human_decision=decisions,  # type: ignore[arg-type]
        evidence_index=evidence_index,
        traces=[],
    )
