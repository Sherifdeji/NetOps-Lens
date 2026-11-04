"""CLI: Stage A assessment, verdict-gated Stage B, and Stage C verification.

``--no-investigate`` skips Stage B and preserves the exact Stage A output:
no Muse or Meta API calls exist on that path. Default runs execute Stage B
while the run-scoped Batfish network is still alive; eligible candidates
are then applied and independently verified (Stage C), human decisions are
collected, the final report is assembled exactly once, and cleanup happens
only after the complete pipeline finishes.
"""

from __future__ import annotations

import argparse
import shutil
import sys
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import NoReturn

import yaml

from netops_lens.agent import run_stage_b
from netops_lens.assessment import AssessmentError, run_mandatory_assessment
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
    AclDeny,
    AclPermit,
    AddStaticRoute,
    ApplicationResult,
    AssessmentResult,
    CandidatePatch,
    HumanDecision,
    Intent,
    InvestigationResult,
    RemoveAclLine,
    RemoveStaticRoute,
    Report,
    SnapshotRef,
    VerificationResult,
)
from netops_lens.patch import apply_candidate
from netops_lens.report import ReportError, assemble_report
from netops_lens.verify import empty_skeleton, verify_candidate

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


class Exit1ArgumentParser(argparse.ArgumentParser):
    """Usage errors exit 1 (plan §CLI), not argparse's default 2."""

    def error(self, message: str) -> NoReturn:  # noqa: D102
        self.exit(1, f"{self.prog}: error: {message}\n")


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


def build_parser() -> Exit1ArgumentParser:
    parser = Exit1ArgumentParser(
        prog="netops-lens", description="NetOps Lens V1 (Phase 2: deterministic assessment)"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    assess = sub.add_parser("assess", help="run the mandatory Stage A assessment")
    assess.add_argument("--scenario", help="scenario name from lab/scenarios/manifest.yaml")
    assess.add_argument("--baseline", help="baseline snapshot directory")
    assess.add_argument("--proposed", help="proposed snapshot directory")
    assess.add_argument("--intent", help="intent YAML file")
    assess.add_argument(
        "--question", default="", help="engineer question (accepted; unused in Phase 2)"
    )
    assess.add_argument("--json", action="store_true", help="print the full Report JSON")
    assess.add_argument(
        "--no-investigate",
        action="store_true",
        help="skip Stage B investigation; never affects Stage A",
    )
    assess.add_argument("--out", help="write the full Report JSON to this file")
    assess.add_argument(
        "--manifest",
        default=str(REPO_ROOT / "lab" / "scenarios" / "manifest.yaml"),
        help="scenario manifest path",
    )
    return parser


def _resolve_inputs(args: argparse.Namespace) -> tuple[Path, Path, Path, str]:
    if args.scenario is not None:
        if args.baseline or args.proposed or args.intent:
            raise IntentError("--scenario cannot be combined with --baseline/--proposed/--intent")
        manifest = load_manifest(args.manifest)
        try:
            entry = manifest["scenarios"][args.scenario]
        except KeyError as exc:
            raise IntentError(f"unknown scenario {args.scenario!r}") from exc
        return (
            REPO_ROOT / entry["baseline_path"],
            REPO_ROOT / entry["proposed_path"],
            REPO_ROOT / entry["intent_path"],
            args.scenario,
        )
    if not (args.baseline and args.proposed and args.intent):
        raise IntentError("provide --scenario or all of --baseline/--proposed/--intent")
    return Path(args.baseline), Path(args.proposed), Path(args.intent), "manual"


def _print_investigation(report: Report) -> None:
    investigation = report.investigation
    if investigation is None:
        return
    print("Investigation (Muse Spark):")
    if investigation.narrative:
        for line in investigation.narrative.splitlines():
            print(f"  {line}")
    else:
        print("  (no narrative)")
    print(f"  Tool calls: {len(investigation.tool_activity)}")
    if investigation.candidates:
        for candidate in investigation.candidates:
            ops = ", ".join(op.op for op in candidate.operations)
            print(f"  Candidate {candidate.candidate_id}: {ops}")
    else:
        print("  Candidates: none")


def _print_stage_c(report: Report) -> None:
    """Human-readable Stage C section: per-candidate application and verification."""
    if not report.applications and not report.verifications:
        return
    print("Candidate verification (Stage C):")
    ver_by_id = {verification.candidate_id: verification for verification in report.verifications}
    for app in report.applications:
        status = "applied" if app.applied else "FAILED"
        print(f"  Candidate {app.candidate_id}: application {status}")
        for diff in app.diff:
            print(f"    {diff.file}:")
            for line in diff.removed:
                print(f"      - {line}")
            for line in diff.added:
                print(f"      + {line}")
        verification = ver_by_id.get(app.candidate_id)
        if verification is not None:
            print(f"    verification: {verification.status}")
            for check in verification.checks:
                print(f"      {check.name}: {check.outcome} ({check.detail})")
                if check.evidence_ids:
                    print(f"        evidence: {', '.join(check.evidence_ids)}")
            for reason in verification.reasons:
                print(f"    reason: {reason}")
        decision = report.human_decision.get(app.candidate_id, "PENDING")
        print(f"    human decision: {decision}")
    print("  Note: APPROVED means human approval of the analysis result only,")
    print("  not deployment or execution on any device.")


def _print_human(report: Report, *, tag: str) -> None:
    assessment = report.assessment
    print(f"NetOps Lens assessment [{tag}]")
    print(f"Verdict: {assessment.verdict}")
    print("Flow comparisons:")
    if not assessment.flow_comparisons:
        print("  (no declared flows)")
    for comparison in assessment.flow_comparisons:
        print(
            f"  {comparison.flow_id} [{comparison.kind}]: "
            f"{comparison.baseline_reach} -> {comparison.proposed_reach} "
            f"=> {comparison.classification}"
        )
    print("Findings:")
    if not assessment.findings:
        print("  (none)")
    for finding in assessment.findings:
        evidence = ", ".join(finding.evidence_ids)
        scope = f"flow {finding.flow_id}" if finding.flow_id else "snapshot health"
        print(f"  {finding.finding_id} [{finding.claim_type.value}] {scope}: {finding.statement}")
        print(f"    evidence: {evidence}")
    if assessment.inconclusive_reasons:
        print("Inconclusive reasons:")
        for reason in assessment.inconclusive_reasons:
            print(f"  - {reason}")
    print("Snapshot health:")
    for health in assessment.health:
        detail = "; ".join(health.reasons) if health.reasons else "clean"
        print(f"  {health.snapshot}: {health.status} ({detail})")
    if assessment.verdict == "NO_REGRESSION_DETECTED":
        print("Note: only tested flows are covered; untested traffic is not claimed safe.")
    _print_investigation(report)
    _print_stage_c(report)


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


def cleanup_run_network(client: BatfishClient, *, protected: str | None = None) -> bool:
    """Best-effort deletion of a run-scoped network. Never raises.

    The configured shared network is never deleted: when the client's
    network equals ``protected``, cleanup is refused with a warning.
    Cleanup failure never erases the final report or changes the exit code;
    the caller owns both before calling this.
    """
    try:
        network = client.network
    except AttributeError:
        network = None
    if protected is not None and network == protected:
        print(
            f"warning: refusing to delete protected network {protected!r}",
            file=sys.stderr,
        )
        return False
    try:
        client.delete_network()
    except BatfishError as exc:
        print(f"warning: run network cleanup failed: {exc}", file=sys.stderr)
        return False
    return True


def _warn(message: str) -> None:
    print(f"warning: {message}", file=sys.stderr)


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


def _describe_op(op: object) -> str:
    if isinstance(op, AddStaticRoute):
        return f"add_static_route {op.node} {op.prefix} via {op.next_hop}"
    if isinstance(op, RemoveStaticRoute):
        return f"remove_static_route {op.node} {op.prefix} via {op.next_hop}"
    if isinstance(op, (RemoveAclLine, AclPermit, AclDeny)):
        return f"{op.op} {op.node} {op.acl} seq {op.sequence_number}"
    return getattr(op, "op", "?")  # type: ignore[no-any-return]


def _remove_candidate_dir(cand_dir: Path, ephemeral_root: Path) -> None:
    """Remove one directory created by this run's application step.

    Only a directory strictly inside the current run's ephemeral root is
    removed; anything else is refused with a warning. Never raises.
    """
    try:
        if cand_dir.is_symlink():
            _warn(
                f"candidate directory cleanup refused for {cand_dir.name}: "
                "not a real directory"
            )
            return
        root = ephemeral_root.resolve()
        target = cand_dir.resolve()
    except OSError as exc:
        _warn(f"candidate directory cleanup failed for {cand_dir.name}: {exc}")
        return
    if target == root or root not in target.parents:
        _warn(
            f"candidate directory cleanup refused for {cand_dir.name}: "
            "outside the run ephemeral root"
        )
        return
    try:
        shutil.rmtree(target)
    except OSError as exc:
        _warn(f"candidate directory cleanup failed for {cand_dir.name}: {exc}")


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
                _warn(f"candidate snapshot cleanup failed for {snap_name!r}: {exc}")
    finally:
        if not settings.keep_candidate_dirs:
            _remove_candidate_dir(cand_dir, ephemeral_root)
    return app_result, verification


def _remove_empty_run_root(root: Path) -> None:
    """Remove this run's ephemeral root, but only when it is empty.

    Never removes the shared ``runs/`` directory or a non-empty directory.
    Cleanup failure warns on stderr without masking candidate results.
    """
    try:
        if root.is_dir() and not any(root.iterdir()):
            root.rmdir()
    except OSError as exc:
        _warn(f"run ephemeral root cleanup failed for {root.name}: {exc}")


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
        _remove_empty_run_root(root)
    return applications, verifications


def _summarize_candidate(
    candidate: CandidatePatch,
    app: ApplicationResult,
    verification: VerificationResult | None,
) -> str:
    ops = "; ".join(_describe_op(op) for op in candidate.operations)
    lines = [
        f"Candidate {candidate.candidate_id} [{candidate.rationale}]",
        f"  Operations: {ops}",
        f"  Targets: {', '.join(candidate.target_flow_ids)}",
        f"  Application: {'applied' if app.applied else 'FAILED'}",
    ]
    if app.applied:
        lines.append(f"  Changed: {', '.join(app.changed_files) or '(none)'}")
    elif app.reasons:
        lines.append(f"  Application reasons: {'; '.join(app.reasons)}")
    if verification is not None:
        lines.append(f"  Verification: {verification.status}")
        for check in verification.checks:
            lines.append(f"    {check.name}: {check.outcome} ({check.detail})")
    return "\n".join(lines)


def _collect_decisions(
    candidates: list[CandidatePatch],
    applications: list[ApplicationResult],
    verifications: list[VerificationResult],
    *,
    json_mode: bool,
    tty: bool,
    ask: Callable[[str], str] | None = None,
) -> dict[str, HumanDecision]:
    """Record one human decision per candidate; interactive only for VERIFIED.

    Summaries, prompts, and warnings go to stderr so stdout stays reserved
    for the final report. An interrupted input (EOFError/KeyboardInterrupt)
    records PENDING for the current and all remaining candidates and stops
    prompting; the run continues to report assembly with its exit code intact.
    """
    # The adapter takes the prompt text for signature compatibility but the
    # text is already on stderr, so nothing is printed to stdout by input().
    prompt = ask if ask is not None else (lambda message: input())
    app_by_id = {app.candidate_id: app for app in applications}
    ver_by_id = {verification.candidate_id: verification for verification in verifications}
    decisions: dict[str, HumanDecision] = {}
    for index, candidate in enumerate(candidates):
        verification = ver_by_id.get(candidate.candidate_id)
        if (
            verification is not None
            and verification.status == "VERIFIED"
            and not json_mode
            and tty
        ):
            app = app_by_id.get(candidate.candidate_id)
            if app is None:  # defensive; run_stage_c always pairs them
                decisions[candidate.candidate_id] = "PENDING"
                continue
            print(_summarize_candidate(candidate, app, verification), file=sys.stderr)
            print(
                f"Candidate {candidate.candidate_id} is VERIFIED.\n\n"
                "[a]pprove / [r]eject / [s]kip: ",
                file=sys.stderr,
            )
            try:
                choice = prompt("").strip().lower()
            except (EOFError, KeyboardInterrupt):
                _warn(
                    "human input interrupted; "
                    "recording PENDING for the remaining candidates"
                )
                for rest in candidates[index:]:
                    decisions[rest.candidate_id] = "PENDING"
                break
            if choice == "a":
                decisions[candidate.candidate_id] = "APPROVED"
            elif choice == "r":
                decisions[candidate.candidate_id] = "REJECTED"
            else:
                decisions[candidate.candidate_id] = "PENDING"
        else:
            decisions[candidate.candidate_id] = "PENDING"
    return decisions


def run_assess(args: argparse.Namespace) -> int:
    try:
        settings = load_settings()
    except RuntimeError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 1
    try:
        baseline_dir, proposed_dir, intent_path, tag = _resolve_inputs(args)
        intent: Intent = load_intent(intent_path)
    except IntentError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return 1
    client = BatfishClient(
        settings.batfish_host, run_network_name(settings.batfish_network, tag)
    )
    baseline_ref = SnapshotRef(name=f"{tag}-baseline", path=str(baseline_dir))
    proposed_ref = SnapshotRef(name=f"{tag}-proposed", path=str(proposed_dir))
    exit_code = 1
    try:
        try:
            # N-03: connect lives inside the guarded region so even a
            # partially failed setup attempts cleanup of this run's network.
            client.connect()
        except BatfishError as exc:
            print(f"Batfish unavailable: {exc}", file=sys.stderr)
            exit_code = 1
            return exit_code
        try:
            client.init_snapshot(baseline_dir, baseline_ref.name)
            client.init_snapshot(proposed_dir, proposed_ref.name)
        except BatfishError as exc:
            print(f"snapshot error: {exc}", file=sys.stderr)
            exit_code = 1
            return exit_code
        store = EvidenceStore()
        try:
            assessment = run_mandatory_assessment(
                client, store, baseline_ref, proposed_ref, intent
            )
            if args.no_investigate:
                investigation = None
            else:
                # Stage B runs while the run-scoped network is still alive;
                # it never raises and never mutates the Stage A assessment.
                investigation = run_stage_b(
                    client,
                    store,
                    assessment,
                    intent,
                    baseline_ref,
                    proposed_ref,
                    question=args.question,
                )
            applications: list[ApplicationResult] = []
            verifications: list[VerificationResult] = []
            decisions: dict[str, HumanDecision] = {}
            if _stage_c_should_run(
                assessment, investigation, no_investigate=args.no_investigate
            ):
                assert investigation is not None
                applications, verifications = run_stage_c(
                    client=client,
                    store=store,
                    settings=settings,
                    assessment=assessment,
                    investigation=investigation,
                    intent=intent,
                    baseline_ref=baseline_ref,
                    proposed_ref=proposed_ref,
                    proposed_dir=proposed_dir,
                    tag=tag,
                )
                decisions = _collect_decisions(
                    investigation.candidates,
                    applications,
                    verifications,
                    json_mode=args.json,
                    tty=sys.stdin.isatty(),
                )
            report = assemble_report(
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
        except (AssessmentError, ReportError) as exc:
            print(f"assessment error: {exc}", file=sys.stderr)
            return 1
        if args.json:
            print(report.model_dump_json(indent=2))
        else:
            _print_human(report, tag=tag)
        if args.out:
            Path(args.out).write_text(report.model_dump_json(indent=2) + "\n")
        exit_code = (
            0 if assessment.verdict in ("REGRESSION_DETECTED", "NO_REGRESSION_DETECTED") else 2
        )
    finally:
        # The report is already printed; cleanup failure keeps the exit code.
        # The protected argument is the shared network: it is never deleted.
        cleanup_run_network(client, protected=settings.batfish_network)
    return exit_code


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "assess":
        return run_assess(args)
    parser.error(f"unknown command {args.command!r}")
    return 1  # pragma: no cover - error() exits


if __name__ == "__main__":
    sys.exit(main())
