"""Reusable application-level assessment pipeline (Phase 5.1).

Stage A -> Stage B -> Stage C orchestration lives here so every frontend
(CLI today, Streamlit in Phase 5.2) shares one backend entry point:
:func:`run_assessment_pipeline`. Each call creates a fresh execution
context (client, run-scoped network, evidence store, candidate working
directories), assembles the complete :class:`Report` with every human
decision ``PENDING``, cleans up its resources, and returns. The pipeline
never prints, never prompts on stdin, never exits the process, and never
imports UI functionality.
"""

from __future__ import annotations

import shutil
import uuid
from collections.abc import Callable
from pathlib import Path

import yaml

from netops_lens.agent import Transport, run_stage_b
from netops_lens.assessment import run_mandatory_assessment
from netops_lens.batfish_client import (
    BatfishClient,
    BatfishError,
    candidate_snapshot_name,
    is_candidate_snapshot_name,
)
from netops_lens.config import Settings, load_settings
from netops_lens.evidence import EvidenceStore
from netops_lens.intent import IntentError, load_intent
from netops_lens.models import (
    ApplicationResult,
    AssessmentResult,
    CandidatePatch,
    HumanDecision,
    Intent,
    InvestigationResult,
    NetOpsModel,
    Report,
    SnapshotRef,
    VerificationResult,
)
from netops_lens.patch import apply_candidate
from netops_lens.report import assemble_report
from netops_lens.verify import empty_skeleton, verify_candidate

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


class AssessmentRequest(NetOpsModel):
    """Typed pipeline input: scenario shortcut or manual snapshot triple.

    Either ``scenario`` (resolved through the scenario manifest) or all of
    ``baseline``/``proposed``/``intent`` must be supplied. ``manifest``
    overrides the manifest path (the CLI ``--manifest`` flag); ``question``
    is the free-text engineer question; ``no_investigate`` preserves the
    exact Stage A output while skipping Stage B (and therefore Stage C).
    """

    scenario: str | None = None
    baseline: str | None = None
    proposed: str | None = None
    intent: str | None = None
    manifest: str | None = None
    question: str = ""
    no_investigate: bool = False


class PipelineConnectionError(BatfishError):
    """The run client could not connect/select its run-scoped network.

    A subclass of :class:`BatfishError` so ``except BatfishError`` still
    catches it; the CLI maps it to "Batfish unavailable" while snapshot
    initialization failures map to "snapshot error".
    """


# Stage B seam type: the production implementation is ``run_stage_b``; the
# CLI forwards its own module global so existing ``run_stage_b`` patches
# keep working, and tests may inject scripted variants.
StageBFn = Callable[..., InvestigationResult]


def load_manifest(path: str | Path) -> dict:
    """Load and minimally validate the scenario manifest."""
    manifest_path = Path(path)
    if not manifest_path.is_file():
        raise IntentError(f"manifest not found: {manifest_path}")
    try:
        with open(manifest_path) as fh:
            data = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        raise IntentError(f"malformed manifest YAML: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("scenarios"), dict):
        raise IntentError(f"{manifest_path}: expected a 'scenarios' mapping")
    return data


def resolve_assessment_inputs(request: AssessmentRequest) -> tuple[Path, Path, Path, str]:
    """Resolve a request to (baseline_dir, proposed_dir, intent_path, tag)."""
    if request.scenario is not None:
        if request.baseline or request.proposed or request.intent:
            raise IntentError("--scenario cannot be combined with --baseline/--proposed/--intent")
        default_manifest = REPO_ROOT / "lab" / "scenarios" / "manifest.yaml"
        manifest = load_manifest(request.manifest or default_manifest)
        try:
            entry = manifest["scenarios"][request.scenario]
        except KeyError as exc:
            raise IntentError(f"unknown scenario {request.scenario!r}") from exc
        return (
            REPO_ROOT / entry["baseline_path"],
            REPO_ROOT / entry["proposed_path"],
            REPO_ROOT / entry["intent_path"],
            request.scenario,
        )
    if not (request.baseline and request.proposed and request.intent):
        raise IntentError("provide --scenario or all of --baseline/--proposed/--intent")
    return Path(request.baseline), Path(request.proposed), Path(request.intent), "manual"


def run_network_name(prefix: str, tag: str) -> str:
    """Unique Batfish network for one assessment run.

    N-03: the configured ``BATFISH_NETWORK`` value is the prefix, so runs
    stay visibly grouped with the deployment they belong to. The tag and a
    random suffix keep concurrent runs isolated from each other. Names stay
    lowercase alphanumeric-plus-dash, and the suffix guarantees the name
    can never equal the shared configured network itself.
    """
    def safe(text: str) -> str:
        return "".join(c if c.isalnum() else "-" for c in text.lower())

    return f"{safe(prefix)}-{safe(tag)}-{uuid.uuid4().hex[:8]}"


def _stderr_warning(message: str) -> None:
    import sys

    print(f"warning: {message}", file=sys.stderr)


def cleanup_run_network(
    client: BatfishClient,
    *,
    protected: str | None = None,
    on_warning: Callable[[str], None] | None = None,
) -> bool:
    """Best-effort deletion of a run-scoped network. Never raises.

    The configured shared network is never deleted: when the client's
    network equals ``protected``, cleanup is refused with a warning.
    Cleanup failure never erases the final report. The default warning
    goes to stderr; the pipeline passes its own handler (silent unless
    the caller supplied one) so library use never prints.
    """
    warn = on_warning if on_warning is not None else _stderr_warning
    try:
        network = client.network
    except AttributeError:
        network = None
    if protected is not None and network == protected:
        warn(f"refusing to delete protected network {protected!r}")
        return False
    try:
        client.delete_network()
    except BatfishError as exc:
        warn(f"run network cleanup failed: {exc}")
        return False
    return True


def _stage_c_should_run(
    assessment: AssessmentResult,
    investigation: InvestigationResult | None,
    *,
    no_investigate: bool,
) -> bool:
    """Stage C runs only on a valid regression with submitted candidates."""
    return (
        not no_investigate
        and assessment.verdict == "REGRESSION_DETECTED"
        and investigation is not None
        and bool(investigation.candidates)
    )


def _ephemeral_root(tag: str) -> Path:
    """Create this run's isolated candidate directory root under runs/."""
    safe = "".join(c if c.isalnum() else "-" for c in tag.lower())
    root = REPO_ROOT / "runs" / f"{safe}-{uuid.uuid4().hex[:8]}"
    root.mkdir(parents=True)
    return root


def _remove_candidate_dir(
    cand_dir: Path, ephemeral_root: Path, warn: Callable[[str], None]
) -> None:
    """Remove one directory created by this run's application step.

    Only a directory strictly inside the current run's ephemeral root is
    removed; anything else is refused with a warning. Never raises.
    """
    try:
        if cand_dir.is_symlink():
            warn(
                f"candidate directory cleanup refused for {cand_dir.name}: "
                "not a real directory"
            )
            return
        root = ephemeral_root.resolve()
        target = cand_dir.resolve()
    except OSError as exc:
        warn(f"candidate directory cleanup failed for {cand_dir.name}: {exc}")
        return
    if target == root or root not in target.parents:
        warn(
            f"candidate directory cleanup refused for {cand_dir.name}: "
            "outside the run ephemeral root"
        )
        return
    try:
        shutil.rmtree(target)
    except OSError as exc:
        warn(f"candidate directory cleanup failed for {cand_dir.name}: {exc}")


def _process_candidate(
    *,
    client: BatfishClient,
    store: EvidenceStore,
    settings: Settings,
    candidate: CandidatePatch,
    assessment: AssessmentResult,
    intent: Intent,
    baseline_ref: SnapshotRef,
    proposed_ref: SnapshotRef,
    proposed_dir: Path,
    ephemeral_root: Path,
    tag: str,
    warn: Callable[[str], None],
) -> tuple[ApplicationResult, VerificationResult]:
    """Apply and independently verify one candidate (Steps 1-6)."""
    candidate_id = candidate.candidate_id
    app_result, cand_dir = apply_candidate(
        candidate,
        proposed_dir=proposed_dir,
        ephemeral_root=ephemeral_root,
        keep_failed_dirs=settings.keep_candidate_dirs,
    )
    if not app_result.applied or cand_dir is None:
        detail = "; ".join(app_result.reasons) or "no reason recorded"
        verification = empty_skeleton(
            candidate_id, None, intent, f"application failed: {detail}"
        )
        return app_result, verification

    # From here on the candidate directory exists and belongs to this run.
    # The finally block guarantees its cleanup on every later exit path
    # (name failure, collision, init failure, registration failure,
    # verification outcome, verifier exception) when retention is off.
    try:
        try:
            snap_name = candidate_snapshot_name(tag, candidate_id)
        except BatfishError as exc:
            return app_result, empty_skeleton(
                candidate_id, None, intent, f"invalid candidate snapshot name: {exc}"
            )
        if snap_name in (baseline_ref.name, proposed_ref.name):
            return app_result, empty_skeleton(
                candidate_id,
                None,
                intent,
                f"candidate snapshot name {snap_name!r} collides with a protected snapshot",
            )
        if client.is_registered_candidate(snap_name):
            return app_result, empty_skeleton(
                candidate_id,
                None,
                intent,
                f"candidate snapshot {snap_name!r} already used in this run",
            )
        try:
            client.init_snapshot(cand_dir, snap_name, overwrite=False)
        except BatfishError as exc:
            return app_result, empty_skeleton(
                candidate_id,
                None,
                intent,
                f"candidate snapshot initialization failed: {exc}",
            )
        try:
            client.register_candidate_snapshot(snap_name)
        except BatfishError as exc:
            # Generated names always validate; a failure here is unexpected and
            # leaves an untracked snapshot, so neither verify nor delete it.
            # The run-scoped network cleanup remains the backstop.
            return app_result, empty_skeleton(
                candidate_id,
                None,
                intent,
                f"candidate snapshot registration failed: {exc}",
            )
        candidate_ref = SnapshotRef(name=snap_name, path=str(cand_dir))
        if not is_candidate_snapshot_name(
            candidate_ref.name
        ) or not client.is_registered_candidate(candidate_ref.name):
            return app_result, empty_skeleton(
                candidate_id, None, intent, "candidate snapshot identity check failed"
            )
        try:
            verification = verify_candidate(
                client,
                store,
                candidate_id=candidate_id,
                baseline_ref=baseline_ref,
                candidate_ref=candidate_ref,
                intent=intent,
                stage_a=assessment,
            )
        except Exception as exc:  # defensive: verify is total, but never lose the run
            verification = empty_skeleton(
                candidate_id,
                snap_name,
                intent,
                f"verification raised {type(exc).__name__}",
            )
        finally:
            try:
                client.delete_snapshot(snap_name)
            except BatfishError as exc:
                warn(f"candidate snapshot cleanup failed for {snap_name!r}: {exc}")
    finally:
        if not settings.keep_candidate_dirs:
            _remove_candidate_dir(cand_dir, ephemeral_root, warn)
    return app_result, verification


def _remove_empty_run_root(root: Path, warn: Callable[[str], None]) -> None:
    """Remove this run's ephemeral root, but only when it is empty.

    Never removes the shared ``runs/`` directory or a non-empty directory.
    Cleanup failure warns without masking candidate results.
    """
    try:
        if root.is_dir() and not any(root.iterdir()):
            root.rmdir()
    except OSError as exc:
        warn(f"run ephemeral root cleanup failed for {root.name}: {exc}")


def run_stage_c(
    *,
    client: BatfishClient,
    store: EvidenceStore,
    settings: Settings,
    assessment: AssessmentResult,
    investigation: InvestigationResult,
    intent: Intent,
    baseline_ref: SnapshotRef,
    proposed_ref: SnapshotRef,
    proposed_dir: Path,
    tag: str,
    warn: Callable[[str], None],
) -> tuple[list[ApplicationResult], list[VerificationResult]]:
    """Apply and verify every submitted candidate independently.

    Candidates never share directories or snapshots; one candidate's
    failure never prevents later candidates from being evaluated.
    """
    applications: list[ApplicationResult] = []
    verifications: list[VerificationResult] = []
    try:
        root = _ephemeral_root(tag)
    except OSError as exc:
        reason = f"cannot create run ephemeral root: {type(exc).__name__}"
        for candidate in investigation.candidates:
            applications.append(
                ApplicationResult(
                    candidate_id=candidate.candidate_id, applied=False, reasons=(reason,)
                )
            )
            verifications.append(empty_skeleton(candidate.candidate_id, None, intent, reason))
        return applications, verifications
    for candidate in investigation.candidates:
        try:
            app_result, verification = _process_candidate(
                client=client,
                store=store,
                settings=settings,
                candidate=candidate,
                assessment=assessment,
                intent=intent,
                baseline_ref=baseline_ref,
                proposed_ref=proposed_ref,
                proposed_dir=proposed_dir,
                ephemeral_root=root,
                tag=tag,
                warn=warn,
            )
        except Exception as exc:  # never lose the run or later candidates
            detail = f"candidate processing raised {type(exc).__name__}"
            app_result = ApplicationResult(
                candidate_id=candidate.candidate_id, applied=False, reasons=(detail,)
            )
            verification = empty_skeleton(candidate.candidate_id, None, intent, detail)
        applications.append(app_result)
        verifications.append(verification)
    if not settings.keep_candidate_dirs:
        _remove_empty_run_root(root, warn)
    return applications, verifications


def run_assessment_pipeline(
    request: AssessmentRequest,
    *,
    settings: Settings | None = None,
    transport: Transport | None = None,
    client_factory: Callable[[str, str], BatfishClient] | None = None,
    stage_b: StageBFn | None = None,
    on_warning: Callable[[str], None] | None = None,
) -> Report:
    """Run Stage A -> Stage B -> Stage C and return the complete report.

    Each call builds a fresh execution context: a new client, a unique
    run-scoped network, a new evidence store, and isolated candidate
    working directories. The returned report carries every human decision
    as ``PENDING``; recording approvals is the caller's job (see
    ``report.apply_human_decisions``).

    The pipeline never prints, never prompts on stdin, and never exits
    the process. Failures surface as exceptions: ``IntentError`` for bad
    inputs, ``PipelineConnectionError`` when the run network cannot be
    reached, ``BatfishError`` for snapshot failures, and
    ``AssessmentError``/``ReportError`` for internal assessment or report
    failures. Resource cleanup (candidate snapshots, candidate
    directories, the run-scoped network) runs in ``finally`` blocks on
    every path. ``on_warning`` receives best-effort cleanup warnings; by
    default they are dropped so library use stays silent.
    """
    resolved = settings if settings is not None else load_settings()
    # Silent by default: a library/Streamlit caller must opt in to warnings.
    warn: Callable[[str], None] = on_warning if on_warning is not None else (lambda _m: None)
    baseline_dir, proposed_dir, intent_path, tag = resolve_assessment_inputs(request)
    intent: Intent = load_intent(intent_path)
    make_client = client_factory if client_factory is not None else BatfishClient
    run_stage_b_fn = stage_b if stage_b is not None else run_stage_b
    client = make_client(resolved.batfish_host, run_network_name(resolved.batfish_network, tag))
    baseline_ref = SnapshotRef(name=f"{tag}-baseline", path=str(baseline_dir))
    proposed_ref = SnapshotRef(name=f"{tag}-proposed", path=str(proposed_dir))
    try:
        try:
            # N-03: connect lives inside the guarded region so even a
            # partially failed setup attempts cleanup of this run's network.
            client.connect()
        except BatfishError as exc:
            raise PipelineConnectionError(str(exc)) from exc
        client.init_snapshot(baseline_dir, baseline_ref.name)
        client.init_snapshot(proposed_dir, proposed_ref.name)
        store = EvidenceStore()
        assessment = run_mandatory_assessment(
            client, store, baseline_ref, proposed_ref, intent
        )
        if request.no_investigate:
            investigation = None
        else:
            # Stage B runs while the run-scoped network is still alive;
            # it never raises and never mutates the Stage A assessment.
            investigation = run_stage_b_fn(
                client,
                store,
                assessment,
                intent,
                baseline_ref,
                proposed_ref,
                question=request.question,
                settings=resolved,
                transport=transport,
            )
        applications: list[ApplicationResult] = []
        verifications: list[VerificationResult] = []
        if _stage_c_should_run(
            assessment, investigation, no_investigate=request.no_investigate
        ):
            assert investigation is not None
            applications, verifications = run_stage_c(
                client=client,
                store=store,
                settings=resolved,
                assessment=assessment,
                investigation=investigation,
                intent=intent,
                baseline_ref=baseline_ref,
                proposed_ref=proposed_ref,
                proposed_dir=proposed_dir,
                tag=tag,
                warn=warn,
            )
        decisions: dict[str, HumanDecision] = {
            app.candidate_id: "PENDING" for app in applications
        }
        return assemble_report(
            assessment,
            store,
            expected_flow_ids=[
                f.flow_id for f in (*intent.must_reach, *intent.must_not_reach)
            ],
            investigation=investigation,
            applications=applications,
            verifications=verifications,
            human_decision=decisions,
        )
    finally:
        # The report is already assembled; cleanup failure keeps it intact.
        # The protected argument is the shared network: it is never deleted.
        cleanup_run_network(client, protected=resolved.batfish_network, on_warning=warn)
