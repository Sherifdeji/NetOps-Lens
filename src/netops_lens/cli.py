"""First functional interface: deterministic assessment over CLI.

Phase 2 runs Stage A only. ``--no-investigate`` is accepted as a safe no-op:
it can never change what Stage A executes. No Muse or Meta API calls exist
on this path.
"""

from __future__ import annotations

import argparse
import sys
import uuid
from pathlib import Path
from typing import NoReturn

import yaml

from netops_lens.assessment import AssessmentError, run_mandatory_assessment
from netops_lens.batfish_client import BatfishClient, BatfishError
from netops_lens.config import load_settings
from netops_lens.evidence import EvidenceStore
from netops_lens.intent import IntentError, load_intent
from netops_lens.models import Intent, Report, SnapshotRef
from netops_lens.report import ReportError, assemble_report

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
        help="Phase 2 no-op: investigation does not exist yet; never affects Stage A",
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
            report = assemble_report(
                assessment,
                store,
                expected_flow_ids=[
                    f.flow_id for f in (*intent.must_reach, *intent.must_not_reach)
                ],
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
