"""Phase 2 report assembly: assessment + evidence index, nothing else.

Investigation and verifications stay empty until Phases 3 and 4. Findings
are never generated from model text — only ``assessment.py`` writes them.
"""

from __future__ import annotations

from collections.abc import Collection

from netops_lens.evidence import EvidenceStore
from netops_lens.models import AssessmentResult, Report


class ReportError(Exception):
    """A report that must not be rendered (e.g., incomplete assessment)."""


def assemble_report(
    assessment: AssessmentResult,
    store: EvidenceStore,
    *,
    expected_flow_ids: Collection[str],
) -> Report:
    """Assemble the Phase 2 report; refuse incomplete assessments loudly."""
    actual = [c.flow_id for c in assessment.flow_comparisons]
    if len(actual) != len(set(actual)) or set(actual) != set(expected_flow_ids):
        raise ReportError(
            "assessment coverage mismatch: "
            f"expected {sorted(expected_flow_ids)}, got {sorted(actual)}"
        )
    evidence_index = {}
    for evidence_id in store.ids():
        record = store.get(evidence_id)
        if record is None:  # pragma: no cover - store is append-only
            raise ReportError(f"evidence {evidence_id} vanished from the store")
        evidence_index[evidence_id] = record
    return Report(
        assessment=assessment,
        investigation=None,
        verifications=[],
        human_decision={},
        evidence_index=evidence_index,
        traces=[],
    )
