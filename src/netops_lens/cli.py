"""CLI: terminal wrapper over the reusable assessment pipeline.

``run_assess`` builds a typed :class:`AssessmentRequest`, runs it through
:func:`pipeline.run_assessment_pipeline` (Stage A -> Stage B -> Stage C
with a fresh execution context per call), then handles terminal-specific
behavior only: human-readable rendering, JSON output, interactive approval
prompts, and exit-code mapping.

``--no-investigate`` skips Stage B and preserves the exact Stage A output:
no Muse or Meta API calls exist on that path.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from pathlib import Path
from typing import NoReturn

from pydantic import ValidationError

from netops_lens.agent import run_stage_b
from netops_lens.assessment import AssessmentError
from netops_lens.batfish_client import BatfishClient, BatfishError
from netops_lens.config import load_settings
from netops_lens.intent import IntentError
from netops_lens.models import (
    AclDeny,
    AclPermit,
    AddStaticRoute,
    ApplicationResult,
    CandidatePatch,
    HumanDecision,
    RemoveAclLine,
    RemoveStaticRoute,
    Report,
    VerificationResult,
)
from netops_lens.pipeline import (
    AssessmentRequest,
    PipelineConnectionError,
    REPO_ROOT,
    cleanup_run_network,
    load_manifest,
    run_assessment_pipeline,
    run_network_name,
)
from netops_lens.report import ReportError, apply_human_decisions

__all__ = [
    "REPO_ROOT",
    "cleanup_run_network",
    "load_manifest",
    "run_network_name",
    "build_parser",
    "run_assess",
    "main",
]


class Exit1ArgumentParser(argparse.ArgumentParser):
    """Usage errors exit 1 (plan §CLI), not argparse's default 2."""

    def error(self, message: str) -> NoReturn:  # noqa: D102
        self.exit(1, f"{self.prog}: error: {message}\n")


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


def _warn(message: str) -> None:
    print(f"warning: {message}", file=sys.stderr)


def _describe_op(op: object) -> str:
    if isinstance(op, AddStaticRoute):
        return f"add_static_route {op.node} {op.prefix} via {op.next_hop}"
    if isinstance(op, RemoveStaticRoute):
        return f"remove_static_route {op.node} {op.prefix} via {op.next_hop}"
    if isinstance(op, (RemoveAclLine, AclPermit, AclDeny)):
        return f"{op.op} {op.node} {op.acl} seq {op.sequence_number}"
    return getattr(op, "op", "?")  # type: ignore[no-any-return]


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
    """Terminal wrapper: request -> reusable pipeline -> decisions -> output."""
    try:
        settings = load_settings()
    except RuntimeError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 1
    try:
        request = AssessmentRequest(
            scenario=args.scenario,
            baseline=args.baseline,
            proposed=args.proposed,
            intent=args.intent,
            manifest=args.manifest,
            question=args.question,
            no_investigate=args.no_investigate,
        )
    except ValidationError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return 1
    try:
        report = run_assessment_pipeline(
            request,
            settings=settings,
            on_warning=_warn,
            # The CLI forwards its own module globals so existing
            # BatfishClient / run_stage_b patches keep working.
            client_factory=lambda host, network: BatfishClient(host, network),
            stage_b=run_stage_b,
        )
    except PipelineConnectionError as exc:
        print(f"Batfish unavailable: {exc}", file=sys.stderr)
        return 1
    except BatfishError as exc:
        print(f"snapshot error: {exc}", file=sys.stderr)
        return 1
    except IntentError as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return 1
    except (AssessmentError, ReportError) as exc:
        print(f"assessment error: {exc}", file=sys.stderr)
        return 1
    # The pipeline returns before any terminal interaction; interactive
    # approval only replaces the all-PENDING decisions via a validated copy.
    if report.applications:
        candidates = (
            report.investigation.candidates if report.investigation is not None else []
        )
        decisions = _collect_decisions(
            candidates,
            report.applications,
            report.verifications,
            json_mode=args.json,
            tty=sys.stdin.isatty(),
        )
        try:
            report = apply_human_decisions(report, decisions)
        except ReportError as exc:
            print(f"assessment error: {exc}", file=sys.stderr)
            return 1
    tag = args.scenario or "manual"
    if args.json:
        print(report.model_dump_json(indent=2))
    else:
        _print_human(report, tag=tag)
    if args.out:
        Path(args.out).write_text(report.model_dump_json(indent=2) + "\n")
    if report.assessment.verdict in ("REGRESSION_DETECTED", "NO_REGRESSION_DETECTED"):
        return 0
    return 2


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "assess":
        return run_assess(args)
    parser.error(f"unknown command {args.command!r}")
    return 1  # pragma: no cover - error() exits


if __name__ == "__main__":
    sys.exit(main())
