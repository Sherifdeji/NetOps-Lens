"""NetOps Lens Streamlit shell + assessment view (Phase 5.2, P52-02).

Session-state contract: this increment manages exactly one key,
``report`` — the completed ``Report`` from the latest successful run. A new
Run replaces the report wholesale; nothing is merged across runs.
Human-decision state (``human_decisions``) is owned by P52-03; the Run
button drops that key if present so no stale decisions survive. Widget
state is owned by Streamlit itself.

What this increment does NOT contain: investigation, candidate,
verification, or human-decision/approval UI (P52-03), and no deployment or
device interaction of any kind. Approval records a decision only, and even
that UI does not exist yet. The verdict shown here always comes directly
from ``Report.assessment.verdict``, which Python alone produces.
"""

from __future__ import annotations

from typing import Any

import streamlit as st

from netops_lens.assessment import AssessmentError
from netops_lens.batfish_client import BatfishError
from netops_lens.intent import IntentError
from netops_lens.models import Report
from netops_lens.pipeline import (
    AssessmentRequest,
    PipelineConnectionError,
    ProgressEvent,
    REPO_ROOT,
    load_manifest,
    run_assessment_pipeline,
)
from netops_lens.report import ReportError

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


if __name__ == "__main__":
    main()
