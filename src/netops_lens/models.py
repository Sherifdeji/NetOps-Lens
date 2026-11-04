"""Pydantic v2 data contracts for NetOps Lens V1.

Every model forbids extra keys and is JSON-serializable. The Stage A
assessment object graph (``AssessmentResult`` and everything reachable from
it) is deeply immutable: frozen models plus tuples, so no caller — and no
later pipeline stage — can mutate a verdict, finding, or health record.
Python-only constructs (findings, verdicts) live here as types; the logic
that produces them belongs to later phases (``assessment.py``, ``evidence.py``).
"""

from __future__ import annotations

from enum import Enum
from ipaddress import IPv4Address, IPv4Network
from typing import Annotated, Literal, Union

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    model_validator,
)

type JsonValue = Union[
    str,
    int,
    float,
    bool,
    None,
    list[JsonValue],
    dict[str, JsonValue],
]
"""Arbitrary JSON payload (tool details/args). Recursive; no ``Any``."""


class NetOpsModel(BaseModel):
    """Shared base: reject unknown keys, keep JSON round-trips exact."""

    model_config = ConfigDict(extra="forbid")


class FrozenModel(BaseModel):
    """Shared base for the immutable assessment graph: frozen + no extras."""

    model_config = ConfigDict(extra="forbid", frozen=True)


EvidenceId = Annotated[str, Field(pattern=r"^ev-[0-9]+$")]
FindingId = Annotated[str, Field(pattern=r"^f-[0-9]+$")]
CandidateId = Annotated[str, Field(pattern=r"^c-[0-9]+$")]


class Protocol(str, Enum):
    ICMP = "ICMP"
    TCP = "TCP"
    UDP = "UDP"


class FlowSpec(NetOpsModel):
    """One declared connectivity requirement (one intent entry)."""

    flow_id: str = Field(min_length=1)
    src_ip: IPv4Address
    dst_ip: IPv4Address
    protocol: Protocol
    dst_port: int | None = Field(default=None, ge=1, le=65535)
    start_location: str = Field(min_length=1)

    @model_validator(mode="after")
    def _check_port(self) -> FlowSpec:
        if self.protocol in (Protocol.TCP, Protocol.UDP) and self.dst_port is None:
            raise ValueError(f"dst_port is required for {self.protocol.value}")
        if self.protocol == Protocol.ICMP and self.dst_port is not None:
            raise ValueError("dst_port is forbidden for ICMP")
        return self


class Intent(NetOpsModel):
    """Parsed ``intent.yaml``: required and prohibited connectivity."""

    version: int = Field(ge=1)
    description: str = ""
    must_reach: list[FlowSpec] = Field(default_factory=list)
    must_not_reach: list[FlowSpec] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique_ids(self) -> Intent:
        ids = [f.flow_id for f in [*self.must_reach, *self.must_not_reach]]
        if len(set(ids)) != len(ids):
            raise ValueError("flow ids must be unique within one intent file")
        return self


class SnapshotRef(NetOpsModel):
    name: str = Field(min_length=1)
    path: str = Field(min_length=1)


class FileParseEntry(FrozenModel):
    """Per-file parse status. Exact status tokens are pinned in Phase 1."""

    file: str = Field(min_length=1)
    status: str = Field(min_length=1)


HealthStatus = Literal["OK", "NOT_OK"]


class SnapshotHealth(FrozenModel):
    """Health of one snapshot. Exactly two states; detail lives in reasons."""

    snapshot: str = Field(min_length=1)
    status: HealthStatus
    per_file_parse: tuple[FileParseEntry, ...] = ()
    init_issues: tuple[str, ...] = ()
    nodes: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()
    benign_warnings: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _check_consistency(self) -> SnapshotHealth:
        if self.status == "OK" and self.reasons:
            raise ValueError("OK snapshot cannot carry blocking reasons")
        if self.status == "NOT_OK" and not self.reasons:
            raise ValueError("NOT_OK snapshot must carry at least one blocking reason")
        return self


ToolStatus = Literal["ok", "error", "inconclusive"]


class ToolResult(NetOpsModel):
    """One backend tool invocation. Never raises across the tool boundary."""

    tool: str = Field(min_length=1)
    snapshots: list[str] = Field(min_length=1)
    flow_id: str | None = None
    status: ToolStatus
    summary: str = ""
    details: dict[str, JsonValue] = Field(default_factory=dict)
    evidence_id: EvidenceId


class EvidenceRecord(NetOpsModel):
    """Stored payload behind one evidence ID (ID minted at tool-return time)."""

    evidence_id: EvidenceId
    tool: str = Field(min_length=1)
    snapshots: list[str] = Field(min_length=1)
    flow_id: str | None = None
    disposition: str | None = None
    details: dict[str, JsonValue] = Field(default_factory=dict)
    created_order: int = Field(ge=0)


class ClaimType(str, Enum):
    REACHABILITY_CHANGED = "REACHABILITY_CHANGED"
    INTENT_SATISFIED = "INTENT_SATISFIED"
    INTENT_VIOLATED = "INTENT_VIOLATED"
    ROUTE_PRESENT = "ROUTE_PRESENT"
    ROUTE_ABSENT = "ROUTE_ABSENT"
    TRACE_DISPOSITION = "TRACE_DISPOSITION"
    SNAPSHOT_HEALTH = "SNAPSHOT_HEALTH"


Reachability = Literal["REACHABLE", "UNREACHABLE", "UNKNOWN"]
FlowKind = Literal["must_reach", "must_not_reach"]
FlowClassification = Literal[
    "REGRESSION", "IMPROVEMENT", "NO_CHANGE_OK", "PRE_EXISTING_VIOLATION", "UNKNOWN"
]


class FlowComparison(FrozenModel):
    flow_id: str = Field(min_length=1)
    kind: FlowKind
    baseline_reach: Reachability
    proposed_reach: Reachability
    classification: FlowClassification


class Finding(FrozenModel):
    """Python-produced factual finding. Model text never becomes a Finding."""

    finding_id: FindingId
    claim_type: ClaimType
    flow_id: str | None = None
    statement: str = Field(min_length=1)
    evidence_ids: tuple[EvidenceId, ...] = Field(min_length=1)
    severity: str = Field(min_length=1)


Verdict = Literal["REGRESSION_DETECTED", "NO_REGRESSION_DETECTED", "INCONCLUSIVE"]


class AssessmentResult(FrozenModel):
    """Immutable Stage A output. The sole writer of verdict and findings."""

    verdict: Verdict
    flow_comparisons: tuple[FlowComparison, ...] = ()
    findings: tuple[Finding, ...] = ()
    inconclusive_reasons: tuple[str, ...] = ()
    health: tuple[SnapshotHealth, ...] = ()


def _check_prefix(value: str) -> str:
    """Validate an IPv4 route prefix (host-bits-set networks rejected)."""
    try:
        return str(IPv4Network(value.strip(), strict=True))
    except ValueError as exc:
        raise ValueError(f"invalid IPv4 prefix: {value!r}") from exc


def _check_next_hop(value: str) -> str:
    """Validate an IPv4 static-route next hop (a plain host address)."""
    try:
        return str(IPv4Address(value.strip()))
    except ValueError as exc:
        raise ValueError(f"invalid IPv4 next hop: {value!r}") from exc


def _check_acl_endpoint(value: str) -> str:
    """Validate an ACL match endpoint: any | host <ip> | <ip> | <ip>/<len>."""
    text = " ".join(value.split())
    if text.lower() == "any":
        return "any"
    if text.lower().startswith("host "):
        try:
            return f"host {IPv4Address(text[5:].strip())}"
        except ValueError as exc:
            raise ValueError(f"invalid ACL host endpoint: {value!r}") from exc
    for parser in (IPv4Address, IPv4Network):
        try:
            parsed = parser(text, strict=True) if parser is IPv4Network else parser(text)
            return str(parsed)
        except ValueError:
            continue
    raise ValueError(
        f"invalid ACL endpoint: {value!r} "
        "(expected 'any', 'host <ip>', '<ip>', or '<ip>/<prefixlen>')"
    )


ACL_PROTOCOLS = ("tcp", "udp", "icmp", "ip")


def _check_acl_protocol(value: str) -> str:
    """Validate an ACL match protocol (V1 IOS vocabulary, case-insensitive)."""
    text = value.strip().lower()
    if text not in ACL_PROTOCOLS:
        raise ValueError(
            f"invalid ACL protocol: {value!r} (expected one of {', '.join(ACL_PROTOCOLS)})"
        )
    return text


IPv4Prefix = Annotated[str, Field(min_length=1), AfterValidator(_check_prefix)]
IPv4NextHop = Annotated[str, Field(min_length=1), AfterValidator(_check_next_hop)]
AclEndpoint = Annotated[str, Field(min_length=1), AfterValidator(_check_acl_endpoint)]
AclProtocol = Annotated[str, Field(min_length=1), AfterValidator(_check_acl_protocol)]


class AclAction(str, Enum):
    PERMIT = "permit"
    DENY = "deny"


class AclRule(NetOpsModel):
    """Full match of one existing ACL line (used as ``expected_rule``).

    ``dst_port`` is optional: broad ACL entries without a service port are
    valid IOS, and ``expected_rule`` must be able to describe them.
    """

    action: AclAction
    src: AclEndpoint
    dst: AclEndpoint
    protocol: AclProtocol
    dst_port: int | None = Field(default=None, ge=1, le=65535)


class AddStaticRoute(NetOpsModel):
    op: Literal["add_static_route"]
    node: str = Field(min_length=1)
    prefix: IPv4Prefix
    next_hop: IPv4NextHop


class RemoveStaticRoute(NetOpsModel):
    op: Literal["remove_static_route"]
    node: str = Field(min_length=1)
    prefix: IPv4Prefix
    next_hop: IPv4NextHop


class AclPermit(NetOpsModel):
    """Targeted port-specific permit: ``dst_port`` is always required."""

    op: Literal["acl_permit"]
    node: str = Field(min_length=1)
    acl: str = Field(min_length=1)
    sequence_number: int = Field(ge=1)
    src: AclEndpoint
    dst: AclEndpoint
    protocol: AclProtocol
    dst_port: int = Field(ge=1, le=65535)


class AclDeny(NetOpsModel):
    """Targeted port-specific deny: ``dst_port`` is always required."""

    op: Literal["acl_deny"]
    node: str = Field(min_length=1)
    acl: str = Field(min_length=1)
    sequence_number: int = Field(ge=1)
    src: AclEndpoint
    dst: AclEndpoint
    protocol: AclProtocol
    dst_port: int = Field(ge=1, le=65535)


class RemoveAclLine(NetOpsModel):
    op: Literal["remove_acl_line"]
    node: str = Field(min_length=1)
    acl: str = Field(min_length=1)
    sequence_number: int = Field(ge=1)
    expected_rule: AclRule


PatchOperation = Annotated[
    Union[
        AddStaticRoute,
        RemoveStaticRoute,
        AclPermit,
        AclDeny,
        RemoveAclLine,
    ],
    Field(discriminator="op"),
]
"""Restricted op allowlist, discriminated by ``op``. No free-text op exists."""


class CandidateSubmission(NetOpsModel):
    """Model-supplied payload for ``submit_candidate_patch`` (no ID)."""

    rationale: str = Field(min_length=1)
    operations: list[PatchOperation] = Field(min_length=1, max_length=5)
    target_flow_ids: list[str] = Field(min_length=1)

    @model_validator(mode="after")
    def _check_targets(self) -> CandidateSubmission:
        if any(not flow_id.strip() for flow_id in self.target_flow_ids):
            raise ValueError("target_flow_ids must be non-blank flow IDs")
        if len(set(self.target_flow_ids)) != len(self.target_flow_ids):
            raise ValueError("target_flow_ids must not contain duplicates")
        return self


class CandidatePatch(CandidateSubmission):
    """Accepted candidate. ``candidate_id`` is assigned by Python on acceptance."""

    candidate_id: CandidateId


class FileDiff(FrozenModel):
    """Touched lines of one changed file, no surrounding context.

    ``file`` is a snapshot-relative path (``configs/r1.cfg``) — never an
    absolute filesystem path. Line texts are stripped, without newlines.
    """

    file: str = Field(min_length=1)
    removed: tuple[str, ...] = ()
    added: tuple[str, ...] = ()


class ApplicationResult(FrozenModel):
    """Outcome of applying one candidate to a disposable proposed copy.

    ``changed_files`` mirrors the ``FileDiff.file`` values. ``applied`` is
    false when validation, rendering, or writing failed; ``reasons`` names
    every blocking cause. Collections are tuples: Stage C results feeding
    the final report stay immutable.
    """

    candidate_id: CandidateId
    applied: bool
    changed_files: tuple[str, ...] = ()
    diff: tuple[FileDiff, ...] = ()
    reasons: tuple[str, ...] = ()


CheckOutcome = Literal["pass", "fail", "unknown"]
"""Per-check status. Lowercase values are the established contract."""


class VerificationCheck(FrozenModel):
    """One named verification requirement with its supporting evidence."""

    name: str = Field(min_length=1)
    outcome: CheckOutcome
    detail: str = ""
    evidence_ids: tuple[EvidenceId, ...] = ()


VerificationStatus = Literal["VERIFIED", "REJECTED", "UNVERIFIABLE"]


class VerificationResult(FrozenModel):
    """Immutable per-candidate verification outcome.

    ``candidate_snapshot`` is the Batfish snapshot name only, never a
    filesystem path; it is None only when no candidate snapshot was ever
    successfully created (application or initialization failure). The
    Phase 4.3 CLI guarantees the name-only form; verify.py double-checks
    the identity before any tool call. ``evidence_ids`` is the
    deterministic, deduplicated union of the per-check evidence IDs in
    check order.
    """

    candidate_id: CandidateId
    status: VerificationStatus
    reasons: tuple[str, ...] = ()
    checks: tuple[VerificationCheck, ...] = ()
    evidence_ids: tuple[EvidenceId, ...] = ()
    candidate_snapshot: str | None = Field(default=None)


class ToolCallLog(NetOpsModel):
    tool: str = Field(min_length=1)
    args: dict[str, JsonValue] = Field(default_factory=dict)
    evidence_id: EvidenceId | None = None
    latency_ms: float | None = Field(default=None, ge=0)


class InvestigationResult(NetOpsModel):
    narrative: str | None = None
    candidates: list[CandidatePatch] = Field(default_factory=list)
    tool_activity: list[ToolCallLog] = Field(default_factory=list)


HumanDecision = Literal["APPROVED", "REJECTED", "PENDING"]


class Report(NetOpsModel):
    assessment: AssessmentResult
    investigation: InvestigationResult | None = None
    applications: list[ApplicationResult] = Field(default_factory=list)
    verifications: list[VerificationResult] = Field(default_factory=list)
    human_decision: dict[CandidateId, HumanDecision] = Field(default_factory=dict)
    evidence_index: dict[EvidenceId, EvidenceRecord] = Field(default_factory=dict)
    traces: list[ToolResult] = Field(default_factory=list)
