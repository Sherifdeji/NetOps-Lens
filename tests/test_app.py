"""Streamlit shell + assessment view tests (deterministic, no backend).

AppTest drives the real ``app.py`` script without a browser. No Batfish,
no Muse calls: the Run-path seam is
``netops_lens.pipeline.run_assessment_pipeline`` — AppTest re-executes
app.py fresh as ``__main__``, so its ``from ... import
run_assessment_pipeline`` rebinds whatever that module attribute is at
script execution time, and patching ``app.run_assessment_pipeline`` (the
test-process import) would never intercept a Run click. Every Run-driving
test below patches the pipeline module attribute with the monkeypatch
fixture and asserts the fake was actually called, so a passing test can
never mean the real pipeline ran.
"""

from __future__ import annotations

import pytest

import app
from netops_lens.models import AssessmentResult, FlowComparison, Report
from netops_lens.pipeline import REPO_ROOT
from streamlit.testing.v1 import AppTest

APP_PATH = str(REPO_ROOT / "app.py")


def _texts(at: AppTest) -> list[str]:
    """Collectors for every human-visible string element."""
    found: list[str] = []
    for group in (
        at.title,
        at.header,
        at.subheader,
        at.markdown,
        at.text,
        at.caption,
        at.info,
        at.success,
        at.warning,
        at.error,
    ):
        for element in group:
            value = getattr(element, "value", "")
            if isinstance(value, str):
                found.append(value)
    for button in at.button:
        label = getattr(button, "label", "")
        if isinstance(label, str):
            found.append(label)
    return found


def test_build_request_scenario_mode_sets_scenario_only():
    request = app.build_request(
        "Scenario", "removed_route", "b", "p", "i", "why?", True
    )
    assert request.scenario == "removed_route"
    assert request.baseline is None
    assert request.proposed is None
    assert request.intent is None
    assert request.question == "why?"
    assert request.no_investigate is True


def test_build_request_manual_mode_sets_paths_only():
    request = app.build_request(
        "Manual paths", None, "base", "prop", "intent.yaml", "", False
    )
    assert request.scenario is None
    assert request.baseline == "base"
    assert request.proposed == "prop"
    assert request.intent == "intent.yaml"
    assert request.question == ""
    assert request.no_investigate is False


def test_verdict_style_maps_all_verdicts():
    assert app.verdict_style("REGRESSION_DETECTED") == "error"
    assert app.verdict_style("NO_REGRESSION_DETECTED") == "success"
    assert app.verdict_style("INCONCLUSIVE") == "warning"
    with pytest.raises(ValueError, match="unknown verdict"):
        app.verdict_style("SOMETHING_ELSE")


def test_initial_load_shows_title_and_run_button_without_verdict():
    at = AppTest.from_file(APP_PATH)
    at.run()
    assert at.exception == [], [str(e) for e in at.exception]
    texts = _texts(at)
    assert any("NetOps Lens" in text for text in texts)
    assert any("Run assessment" in text for text in texts)
    assert not any("Verdict:" in text for text in texts)


def _canned_report() -> Report:
    return Report(
        assessment=AssessmentResult(
            verdict="NO_REGRESSION_DETECTED",
            flow_comparisons=(
                FlowComparison(
                    flow_id="web",
                    kind="must_reach",
                    baseline_reach="REACHABLE",
                    proposed_reach="REACHABLE",
                    classification="NO_CHANGE_OK",
                ),
            ),
            findings=(),
            inconclusive_reasons=(),
            health=(),
        ),
        human_decision={},
    )


def test_render_assessment_shows_verdict_and_scoping_note():
    at = AppTest.from_file(APP_PATH)
    at.session_state["report"] = _canned_report()
    at.run()
    assert at.exception == [], [str(e) for e in at.exception]
    assert "Verdict: NO_REGRESSION_DETECTED" in [s.value for s in at.success]
    assert any(
        "untested traffic" in info.value for info in at.info
    ), "the scoping note must accompany NO_REGRESSION_DETECTED"
    frames = [df.value for df in at.dataframe]
    assert frames, "flow comparisons must render as a table"
    assert any(
        "NO_CHANGE_OK" in frame.astype(str).values for frame in frames
    )


def _regression_report() -> Report:
    return Report(
        assessment=AssessmentResult(
            verdict="REGRESSION_DETECTED",
            flow_comparisons=(
                FlowComparison(
                    flow_id="web",
                    kind="must_reach",
                    baseline_reach="REACHABLE",
                    proposed_reach="UNREACHABLE",
                    classification="REGRESSION",
                ),
            ),
            findings=(),
            inconclusive_reasons=(),
            health=(),
        ),
        human_decision={"c-01": "PENDING"},
    )


def test_run_button_drives_pipeline_and_renders_verdict(monkeypatch):
    import netops_lens.pipeline as pipeline_module

    calls: list = []
    canned = _regression_report()

    def _fake(request, **kwargs):
        calls.append((request, kwargs))
        return canned

    monkeypatch.setattr(pipeline_module, "run_assessment_pipeline", _fake)
    at = AppTest.from_file(APP_PATH)
    at.run()
    assert at.exception == [], [str(e) for e in at.exception]
    default_scenario = at.sidebar.selectbox[0].value
    at.sidebar.button[0].click().run()
    assert at.exception == [], [str(e) for e in at.exception]
    # The fake must have intercepted the run: exactly one call, and the
    # real pipeline (Batfish) never executed.
    assert len(calls) == 1
    request, kwargs = calls[0]
    assert request.scenario == default_scenario
    assert callable(kwargs.get("on_progress"))
    assert callable(kwargs.get("on_warning"))
    assert "Verdict: REGRESSION_DETECTED" in [e.value for e in at.error]
    assert at.session_state["report"] is canned


def test_run_failure_shows_error_and_clears_report(monkeypatch):
    import netops_lens.pipeline as pipeline_module
    from netops_lens.intent import IntentError

    def _boom(request, **kwargs):
        raise IntentError("bad input probe")

    monkeypatch.setattr(pipeline_module, "run_assessment_pipeline", _boom)
    at = AppTest.from_file(APP_PATH)
    at.session_state["report"] = _canned_report()
    at.run()
    at.sidebar.button[0].click().run()
    assert at.exception == [], [str(e) for e in at.exception]
    assert any("bad input probe" in e.value for e in at.error)
    assert not any("Verdict:" in text for text in _texts(at))
    assert "report" not in at.session_state


def test_run_progress_events_do_not_break_run(monkeypatch):
    import netops_lens.pipeline as pipeline_module
    from netops_lens.pipeline import ProgressEvent

    def _fake(request, **kwargs):
        callback = kwargs["on_progress"]
        callback(
            ProgressEvent(
                stage="stage_a", status="completed", detail="REGRESSION_DETECTED"
            )
        )
        callback(
            ProgressEvent(
                stage="stage_c_candidate",
                status="completed",
                detail="c-01: VERIFIED",
            )
        )
        return _regression_report()

    monkeypatch.setattr(pipeline_module, "run_assessment_pipeline", _fake)
    at = AppTest.from_file(APP_PATH)
    at.run()
    at.sidebar.button[0].click().run()
    assert at.exception == [], [str(e) for e in at.exception]
    assert "Verdict: REGRESSION_DETECTED" in [e.value for e in at.error]
    assert at.session_state["report"].assessment.verdict == "REGRESSION_DETECTED"
