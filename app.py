"""NetOps Lens Streamlit shell + assessment view (Phase 5.2, P52-03).

Session-state contract: this increment manages exactly one key,
``report`` — the completed ``Report`` from the latest successful run. A new
Run replaces the report wholesale; nothing is merged across runs.
Human decisions live inside the stored report's ``human_decision`` map;
there is no parallel decisions structure. The Run button drops a legacy
``human_decisions`` key if present so no stale state survives. Widget
state is owned by Streamlit itself.

Approval records a decision only. It does not deploy, push, or apply
anything to any device, and no deployment interaction exists anywhere in
this UI. The verdict shown here always comes directly from
``Report.assessment.verdict``, which Python alone produces.
"""

from __future__ import annotations

from typing import Any

import streamlit as st

from netops_lens.assessment import AssessmentError
from netops_lens.batfish_client import BatfishError
from netops_lens.intent import IntentError
from netops_lens.models import (
    AclDeny,
    AclPermit,
    AddStaticRoute,
    ApplicationResult,
    HumanDecision,
    PatchOperation,
    RemoveAclLine,
    RemoveStaticRoute,
    Report,
)
from netops_lens.pipeline import (
    AssessmentRequest,
    PipelineConnectionError,
    ProgressEvent,
    REPO_ROOT,
    load_manifest,
    run_assessment_pipeline,
)
from netops_lens.report import ReportError, apply_human_decisions

MODE_SCENARIO = "Scenario"
MODE_MANUAL = "Manual paths"
REPORT_KEY = "report"
FUTURE_DECISIONS_KEY = "human_decisions"
MANIFEST_PATH = REPO_ROOT / "lab" / "scenarios" / "manifest.yaml"

_STAGE_LABELS = {
    "stage_a": "Stage A",
    "stage_b": "Stage B",
    "stage_c": "Stage C",
}


def build_request(
    mode: str,
    scenario: str | None,
    baseline: str,
    proposed: str,
    intent: str,
    question: str,
    no_investigate: bool,
) -> AssessmentRequest:
    """Build the typed pipeline request from UI inputs (no validation here).

    Scenario mode sets only the scenario; manual mode sets only the three
    paths. Path/intent validation is the pipeline's job: bad inputs raise
    ``IntentError`` there and the UI displays the message.
    """
    if mode == MODE_SCENARIO:
        return AssessmentRequest(
            scenario=scenario,
            question=question,
            no_investigate=no_investigate,
        )
    return AssessmentRequest(
        baseline=baseline or None,
        proposed=proposed or None,
        intent=intent or None,
        question=question,
        no_investigate=no_investigate,
    )


def verdict_style(verdict: str) -> str:
    """Streamlit severity for a Python-owned verdict."""
    if verdict == "REGRESSION_DETECTED":
        return "error"
    if verdict == "NO_REGRESSION_DETECTED":
        return "success"
    if verdict == "INCONCLUSIVE":
        return "warning"
    raise ValueError(f"unknown verdict: {verdict!r}")


def format_progress_event(event: ProgressEvent) -> str:
    """One deterministic status line per progress event."""
    if event.stage == "stage_c_candidate":
        return event.detail or "candidate update"
    label = _STAGE_LABELS.get(event.stage, event.stage)
    text = f"{label} — {event.status}"
    if event.detail:
        text += f": {event.detail}"
    return text


def make_progress_callback(status: Any) -> Any:
    """Adapt pipeline progress events to ``st.status`` lines.

    ``status`` is the live ``st.status`` container, whose element API is
    dynamic, hence ``Any`` (Streamlit's API forces this; nothing else here
    uses ``Any``). The callback itself never raises: only ``write`` calls,
    which the pipeline already isolates from the assessment anyway.
    """

    def _callback(event: ProgressEvent) -> None:
        status.write(format_progress_event(event))

    return _callback


def render_assessment(report: Report) -> None:
    """Render the Stage A assessment from the stored report only.

    The verdict banner is read directly from
    ``report.assessment.verdict``. Nothing from ``report.investigation``
    is rendered here, whatever it contains.
    """
    verdict = report.assessment.verdict
    style = verdict_style(verdict)
    message = f"Verdict: {verdict}"
    if style == "error":
        st.error(message)
    elif style == "success":
        st.success(message)
    else:
        st.warning(message)
    if verdict == "NO_REGRESSION_DETECTED":
        st.info("Only tested flows are covered; untested traffic is not claimed safe.")

    st.subheader("Flow comparisons")
    rows = [
        {
            "flow": comparison.flow_id,
            "kind": comparison.kind,
            "baseline": comparison.baseline_reach,
            "proposed": comparison.proposed_reach,
            "classification": comparison.classification,
        }
        for comparison in report.assessment.flow_comparisons
    ]
    if rows:
        st.dataframe(rows)
    else:
        st.write("(no declared flows)")

    st.subheader("Findings")
    if report.assessment.findings:
        for finding in report.assessment.findings:
            scope = f"flow {finding.flow_id}" if finding.flow_id else "snapshot health"
            st.write(
                f"{finding.finding_id} [{finding.claim_type.value}] {scope}: "
                f"{finding.statement} "
                f"(evidence: {', '.join(finding.evidence_ids)})"
            )
    else:
        st.write("(no findings)")

    if report.assessment.inconclusive_reasons:
        st.subheader("Inconclusive reasons")
        for reason in report.assessment.inconclusive_reasons:
            st.write(f"- {reason}")

    st.subheader("Snapshot health")
    for health in report.assessment.health:
        detail = "; ".join(health.reasons) if health.reasons else "clean"
        st.write(f"{health.snapshot}: {health.status} ({detail})")

    with st.expander("Evidence"):
        if not report.evidence_index:
            st.write("(no evidence)")
        for evidence_id, record in report.evidence_index.items():
            st.write(
                f"{evidence_id}: tool={record.tool}, "
                f"snapshots={', '.join(record.snapshots)}, "
                f"flow={record.flow_id or '-'}, "
                f"disposition={record.disposition or '-'}"
            )
            with st.expander(f"Record {evidence_id}"):
                st.json(record.model_dump(mode="json"))


def main() -> None:
    """Streamlit entry point (executed as ``__main__``; import has no UI)."""
    st.title("NetOps Lens")

    try:
        manifest = load_manifest(MANIFEST_PATH)
        scenarios = manifest["scenarios"]
        scenario_names = list(scenarios)
    except (IntentError, KeyError) as exc:
        st.error(f"input error: {exc}")
        return
    if not scenario_names:
        st.error("input error: manifest defines no scenarios")
        return

    mode = st.sidebar.radio("Mode", [MODE_SCENARIO, MODE_MANUAL])
    if mode == MODE_SCENARIO:
        scenario = st.sidebar.selectbox("Scenario", scenario_names)
        entry = scenarios.get(scenario, {}) if isinstance(scenarios, dict) else {}
        st.sidebar.write(f"Intent: {entry.get('intent_path', '-')}")
        st.sidebar.write(f"Expected verdict: {entry.get('expected_verdict', '-')}")
        baseline = proposed = intent_path = ""
    else:
        scenario = None
        baseline = st.sidebar.text_input("Baseline snapshot dir")
        proposed = st.sidebar.text_input("Proposed snapshot dir")
        intent_path = st.sidebar.text_input("Intent YAML path")
    question = st.sidebar.text_input("Engineer question")
    no_investigate = st.sidebar.checkbox("Skip AI investigation", value=False)

    if st.sidebar.button("Run assessment"):
        # P52-03 owns human decisions; never carry them into a fresh run.
        st.session_state.pop(FUTURE_DECISIONS_KEY, None)
        request = build_request(
            mode, scenario, baseline, proposed, intent_path, question, no_investigate
        )
        warnings: list[str] = []
        try:
            with st.status("Running assessment…", expanded=True) as status:
                report = run_assessment_pipeline(
                    request,
                    on_progress=make_progress_callback(status),
                    on_warning=warnings.append,
                )
        except IntentError as exc:
            st.error(f"input error: {exc}")
            st.session_state.pop(REPORT_KEY, None)
            return
        except PipelineConnectionError as exc:
            st.error(f"Batfish unavailable: {exc}")
            st.session_state.pop(REPORT_KEY, None)
            return
        except BatfishError as exc:
            st.error(f"snapshot error: {exc}")
            st.session_state.pop(REPORT_KEY, None)
            return
        except (AssessmentError, ReportError) as exc:
            st.error(f"assessment error: {exc}")
            st.session_state.pop(REPORT_KEY, None)
            return
        except Exception as exc:  # never show a traceback as a verdict
            st.error(f"unexpected error ({type(exc).__name__}): {exc}")
            st.session_state.pop(REPORT_KEY, None)
            return
        for warning in warnings:
            st.warning(warning)
        # The only per-run backend object the UI retains: the Report.
        st.session_state[REPORT_KEY] = report

    stored = st.session_state.get(REPORT_KEY)
    if stored is not None:
        render_assessment(stored)
        render_investigation(stored)
        render_candidates(stored)


def describe_op(op: PatchOperation) -> str:
    """One-line display text for a patch operation (display only)."""
    if isinstance(op, (AddStaticRoute, RemoveStaticRoute)):
        return f"{op.op} {op.node} {op.prefix} via {op.next_hop}"
    if isinstance(op, (AclPermit, AclDeny)):
        return (
            f"{op.op} {op.node} {op.acl} seq {op.sequence_number} "
            f"{op.src} {op.dst} {op.protocol} {op.dst_port}"
        )
    if isinstance(op, RemoveAclLine):
        rule = op.expected_rule
        return (
            f"{op.op} {op.node} {op.acl} seq {op.sequence_number} "
            f"expect {rule.action} {rule.src} {rule.dst} "
            f"{rule.protocol} {rule.dst_port}"
        )
    return str(getattr(op, "op", "?"))


def candidate_diff_text(application: ApplicationResult) -> str:
    """Deterministic plain-text rendering of a candidate's file diffs."""
    lines: list[str] = []
    for diff in application.diff:
        lines.append(diff.file)
        lines.extend(f"- {line}" for line in diff.removed)
        lines.extend(f"+ {line}" for line in diff.added)
    return "".join(f"{line}\n" for line in lines)


def render_investigation(report: Report) -> None:
    """Render the bounded Muse Spark investigation (never the verdict)."""
    st.subheader("Investigation (Muse Spark)")
    st.caption(
        "AI-generated explanation of the Python findings above. "
        "It does not change the verdict."
    )
    investigation = report.investigation
    if investigation is None:
        st.write("Investigation was not run for this assessment.")
        return
    st.write(investigation.narrative or "(no narrative)")
    if not investigation.tool_activity:
        st.write("(no tool activity)")
        return
    st.write("Tool activity:")
    for log in investigation.tool_activity:
        latency = f", {log.latency_ms:.0f} ms" if log.latency_ms is not None else ""
        st.write(f"{log.tool} (evidence: {log.evidence_id or '-'}{latency})")
        with st.expander(f"Arguments: {log.tool}"):
            st.json(log.args)


def _record_decision(candidate_id: str, decision: HumanDecision) -> None:
    """Record one human decision on the stored report, then refresh.

    Builds the complete decisions map from the current stored report and
    changes only the clicked candidate. Never reruns the pipeline.
    """
    stored = st.session_state.get(REPORT_KEY)
    if stored is None:
        return
    full_map = dict(stored.human_decision)
    full_map[candidate_id] = decision
    try:
        st.session_state[REPORT_KEY] = apply_human_decisions(stored, full_map)
    except ReportError as exc:
        st.error(str(exc))
        return
    st.rerun()


def render_candidates(report: Report) -> None:
    """Render candidates with independent verification and decision controls."""
    st.subheader("Candidates & independent verification")
    investigation = report.investigation
    candidates = investigation.candidates if investigation is not None else []
    if not candidates:
        st.write("No candidates were proposed.")
        return
    app_by_id = {app.candidate_id: app for app in report.applications}
    ver_by_id = {verification.candidate_id: verification for verification in report.verifications}
    for candidate in candidates:
        candidate_id = candidate.candidate_id
        st.subheader(f"Candidate {candidate_id}")
        st.write(candidate.rationale)
        st.write(f"Targets: {', '.join(candidate.target_flow_ids)}")
        st.dataframe(
            [
                {
                    "op": getattr(op, "op", "?"),
                    "node": getattr(op, "node", "-"),
                    "parameters": describe_op(op),
                }
                for op in candidate.operations
            ]
        )
        application = app_by_id.get(candidate_id)
        verification = ver_by_id.get(candidate_id)
        if application is None or verification is None:
            st.write("no verification record")
            st.write(
                f"Human decision: {report.human_decision.get(candidate_id, 'PENDING')}"
            )
            st.write("Human decision requires VERIFIED status.")
            continue
        st.write(f"Application: {'applied' if application.applied else 'FAILED'}")
        if not application.applied and application.reasons:
            for reason in application.reasons:
                st.write(f"- {reason}")
        if application.diff:
            for diff in application.diff:
                st.write(f"Changed file: {diff.file}")
                st.code(
                    "\n".join(
                        [f"- {line}" for line in diff.removed]
                        + [f"+ {line}" for line in diff.added]
                    )
                )
        elif application.applied:
            st.write("Applied with no diff lines.")
        status = verification.status
        if status == "VERIFIED":
            st.success(f"Verification: {status}")
        elif status == "REJECTED":
            st.error(f"Verification: {status}")
        else:
            st.warning(f"Verification: {status}")
        markers = {"pass": "✓", "fail": "✗", "unknown": "?"}
        for check in verification.checks:
            st.write(
                f"{markers.get(check.outcome, '?')} {check.name}: "
                f"{check.outcome} ({check.detail})"
            )
            if check.evidence_ids:
                st.write(f"evidence: {', '.join(check.evidence_ids)}")
        for reason in verification.reasons:
            st.write(f"- {reason}")
        st.write(
            f"Human decision: {report.human_decision.get(candidate_id, 'PENDING')}"
        )
        st.write(
            "Approval records your decision only. It does not deploy, push, "
            "or apply anything to any device."
        )
        if status == "VERIFIED":
            if st.button(
                f"Approve {candidate_id}", key=f"approve-{candidate_id}"
            ):
                _record_decision(candidate_id, "APPROVED")
            if st.button(f"Reject {candidate_id}", key=f"reject-{candidate_id}"):
                _record_decision(candidate_id, "REJECTED")
            if application.applied and application.diff:
                st.download_button(
                    f"Download diff {candidate_id}",
                    data=candidate_diff_text(application),
                    file_name=f"{candidate_id}-diff.txt",
                    mime="text/plain",
                    key=f"download-{candidate_id}",
                )
        else:
            st.write("Human decision requires VERIFIED status.")


if __name__ == "__main__":
    main()
