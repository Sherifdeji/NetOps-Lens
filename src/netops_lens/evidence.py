"""In-run evidence store: mint IDs, keep payloads, validate references.

Python is the only author of factual findings; this store is what makes
every cited evidence ID resolvable. No natural-language truth validation:
``validate_finding`` checks structure only (existence, flow identity,
snapshot identity, disposition support).
"""

from __future__ import annotations

import json
from collections.abc import Collection

from netops_lens.models import EvidenceRecord, Finding, FlowKind

CheckName = str  # one of: existence, flow_identity, snapshot_identity, disposition_support


class EvidenceStore:
    """Per-run mapping of evidence IDs to stored tool-result payloads."""

    def __init__(self) -> None:
        self._records: dict[str, EvidenceRecord] = {}
        self._counter = 0

    def record(
        self,
        *,
        tool: str,
        snapshots: list[str],
        flow_id: str | None = None,
        disposition: str | None = None,
        details: dict | None = None,
    ) -> str:
        """Store one tool-result payload; return the minted evidence ID."""
        self._counter += 1
        evidence_id = f"ev-{self._counter:04d}"
        self._records[evidence_id] = EvidenceRecord(
            evidence_id=evidence_id,  # type: ignore[arg-type]
            tool=tool,
            snapshots=snapshots,
            flow_id=flow_id,
            disposition=disposition,
            details=details if details is not None else {},
            created_order=self._counter,
        )
        return evidence_id

    def get(self, evidence_id: str) -> EvidenceRecord | None:
        return self._records.get(evidence_id)

    def ids(self) -> list[str]:
        return list(self._records)

    def export_json(self) -> str:
        return json.dumps(
            {ev_id: rec.model_dump(mode="json") for ev_id, rec in self._records.items()},
            indent=2,
        )

    def __len__(self) -> int:
        return len(self._records)


def validate_finding(
    finding: Finding,
    store: EvidenceStore,
    *,
    allowed_snapshots: Collection[str],
    kind: FlowKind | None = None,
    subject_snapshot: str | None = None,
) -> tuple[bool, CheckName | None]:
    """Validate one finding. Returns (ok, failed_check_name | None)."""
    records: list[EvidenceRecord] = []
    for evidence_id in finding.evidence_ids:
        record = store.get(evidence_id)
        if record is None:
            return False, "existence"
        records.append(record)

    if finding.claim_type == "SNAPSHOT_HEALTH":
        if any(r.tool != "get_snapshot_health" or r.flow_id is not None for r in records):
            return False, "flow_identity"
    elif any(r.flow_id != finding.flow_id for r in records):
        return False, "flow_identity"

    allowed = set(allowed_snapshots)
    if any(not set(r.snapshots) <= allowed for r in records):
        return False, "snapshot_identity"

    if not _disposition_supports(finding, records, kind=kind, subject_snapshot=subject_snapshot):
        return False, "disposition_support"
    return True, None


def _record_reachability(record: EvidenceRecord) -> str | None:
    """Map a stored Batfish disposition to REACHABLE/UNREACHABLE (mirrors tools)."""
    disposition = record.disposition
    if disposition == "ACCEPTED":
        return "REACHABLE"
    if disposition == "NO_ROUTE" or (disposition or "").startswith("DENIED"):
        return "UNREACHABLE"
    return None


def _check_records_on_subject(
    records: list[EvidenceRecord], tool: str, subject: str | None, reachability: str
) -> bool:
    return any(
        r.tool == tool
        and _record_reachability(r) == reachability
        and (subject is None or subject in r.snapshots)
        for r in records
    )


def _route_count_reached(records: list[EvidenceRecord], minimum: int) -> bool:
    for record in records:
        if record.tool != "get_routes" or record.details.get("tool_status") != "ok":
            continue
        count = record.details.get("route_count")
        if isinstance(count, int) and count >= minimum:
            return True
    return False


def _disposition_supports(
    finding: Finding,
    records: list[EvidenceRecord],
    *,
    kind: FlowKind | None,
    subject_snapshot: str | None,
) -> bool:
    claim = finding.claim_type
    if claim == "SNAPSHOT_HEALTH":
        return all(r.details.get("tool_status") in ("ok", "error", "inconclusive") for r in records)
    if claim == "INTENT_SATISFIED":
        if kind == "must_reach":
            return _check_records_on_subject(records, "check_intent", subject_snapshot, "REACHABLE")
        if kind == "must_not_reach":
            return _check_records_on_subject(
                records, "check_intent", subject_snapshot, "UNREACHABLE"
            )
        return False
    if claim == "INTENT_VIOLATED":
        if kind == "must_reach":
            return _check_records_on_subject(
                records, "check_intent", subject_snapshot, "UNREACHABLE"
            )
        if kind == "must_not_reach":
            return _check_records_on_subject(records, "check_intent", subject_snapshot, "REACHABLE")
        return False
    if claim == "REACHABILITY_CHANGED":
        reaches = {
            _record_reachability(r) for r in records if r.tool in ("check_intent", "trace_flow")
        }
        return "REACHABLE" in reaches and "UNREACHABLE" in reaches
    if claim == "ROUTE_PRESENT":
        return _route_count_reached(records, minimum=1)
    if claim == "ROUTE_ABSENT":
        return any(
            r.tool == "get_routes"
            and (r.details.get("tool_status") != "ok" or r.details.get("route_found") is False)
            for r in records
        )
    if claim == "TRACE_DISPOSITION":
        return any(
            r.tool in ("trace_flow", "check_intent") and r.disposition is not None for r in records
        )
    return False
