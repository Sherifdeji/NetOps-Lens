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
from netops_lens.models import (
    AclDeny,
    AclPermit,
    AddStaticRoute,
    ApplicationResult,
    AssessmentResult,
    CandidatePatch,
    FileDiff,
    FlowComparison,
    InvestigationResult,
    RemoveAclLine,
    RemoveStaticRoute,
    Report,
    ToolCallLog,
    VerificationCheck,
    VerificationResult,
)
from netops_lens.pipeline import REPO_ROOT
from streamlit.testing.v1 import AppTest
from tests._fakes import differential_row, flow_dict, trace_row

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
        at.code,
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
    assert any("NO_CHANGE_OK" in cell for cell in _frame_cells(frames))


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


def _run_with_failing_pipeline(monkeypatch, error):
    import netops_lens.pipeline as pipeline_module

    def _boom(request, **kwargs):
        raise error

    monkeypatch.setattr(pipeline_module, "run_assessment_pipeline", _boom)
    at = AppTest.from_file(APP_PATH)
    at.session_state["report"] = _canned_report()
    at.run()
    at.sidebar.button[0].click().run()
    assert at.exception == [], [str(e) for e in at.exception]
    return at


def test_run_batfish_unavailable_shows_error_and_clears_report(monkeypatch):
    from netops_lens.pipeline import PipelineConnectionError

    at = _run_with_failing_pipeline(
        monkeypatch, PipelineConnectionError("set_network blew up halfway")
    )
    assert any("Batfish unavailable" in e.value for e in at.error)
    assert not any("Verdict:" in text for text in _texts(at))
    assert "report" not in at.session_state


def test_run_snapshot_error_shows_error_and_clears_report(monkeypatch):
    from netops_lens.batfish_client import BatfishError

    at = _run_with_failing_pipeline(monkeypatch, BatfishError("init failed"))
    assert any("snapshot error" in e.value for e in at.error)
    assert not any("Verdict:" in text for text in _texts(at))
    assert "report" not in at.session_state


def test_run_assessment_error_shows_error_and_clears_report(monkeypatch):
    from netops_lens.report import ReportError

    at = _run_with_failing_pipeline(monkeypatch, ReportError("bad report"))
    assert any("assessment error" in e.value for e in at.error)
    assert not any("Verdict:" in text for text in _texts(at))
    assert "report" not in at.session_state


def test_render_empty_intent_keeps_scoping_qualification():
    at = AppTest.from_file(APP_PATH)
    at.session_state["report"] = Report(
        assessment=AssessmentResult(
            verdict="NO_REGRESSION_DETECTED",
            flow_comparisons=(),
            findings=(),
            inconclusive_reasons=(),
            health=(),
        ),
        human_decision={},
    )
    at.run()
    assert at.exception == [], [str(e) for e in at.exception]
    texts = _texts(at)
    assert "Verdict: NO_REGRESSION_DETECTED" in [s.value for s in at.success]
    assert any("(no declared flows)" in text for text in texts)
    assert any("untested traffic" in text for text in texts)


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


def _full_report() -> Report:
    """Canned regression: VERIFIED c-01 plus a REJECTED c-02 in one report."""
    investigation = InvestigationResult(
        narrative="The database flow regressed in the proposed snapshot.",
        candidates=[
            CandidatePatch(
                candidate_id="c-01",
                rationale="restore the missing static route",
                operations=[
                    {
                        "op": "add_static_route",
                        "node": "r1",
                        "prefix": "198.51.100.0/24",
                        "next_hop": "10.0.12.2",
                    }
                ],
                target_flow_ids=["web"],
            ),
            CandidatePatch(
                candidate_id="c-02",
                rationale="alternative next hop",
                operations=[
                    {
                        "op": "add_static_route",
                        "node": "r1",
                        "prefix": "198.51.100.0/24",
                        "next_hop": "10.0.12.3",
                    }
                ],
                target_flow_ids=["web"],
            ),
        ],
        tool_activity=[
            ToolCallLog(
                tool="trace_flow",
                args={"flow_id": "web", "snapshot": "proposed"},
                evidence_id="ev-0001",
                latency_ms=12.0,
            )
        ],
    )
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
        investigation=investigation,
        applications=[
            ApplicationResult(
                candidate_id="c-01",
                applied=True,
                changed_files=("configs/r1.cfg",),
                diff=(
                    FileDiff(
                        file="configs/r1.cfg",
                        removed=(),
                        added=("ip route 198.51.100.0 255.255.255.0 10.0.12.2",),
                    ),
                ),
                reasons=(),
            ),
            ApplicationResult(
                candidate_id="c-02",
                applied=True,
                changed_files=(),
                diff=(),
                reasons=(),
            ),
        ],
        verifications=[
            VerificationResult(
                candidate_id="c-01",
                status="VERIFIED",
                reasons=(),
                checks=(
                    VerificationCheck(
                        name="candidate_health",
                        outcome="pass",
                        detail="snapshot healthy",
                        evidence_ids=("ev-0001",),
                    ),
                    VerificationCheck(
                        name="reachability_restored",
                        outcome="pass",
                        detail="flow reachable",
                        evidence_ids=("ev-0002",),
                    ),
                ),
                evidence_ids=("ev-0001", "ev-0002"),
                candidate_snapshot="manual-candidate-c-01",
            ),
            VerificationResult(
                candidate_id="c-02",
                status="REJECTED",
                reasons=("regression persists on the candidate",),
                checks=(
                    VerificationCheck(
                        name="candidate_health",
                        outcome="fail",
                        detail="snapshot unhealthy",
                        evidence_ids=(),
                    ),
                ),
                evidence_ids=(),
                candidate_snapshot="manual-candidate-c-02",
            ),
        ],
        human_decision={"c-01": "PENDING", "c-02": "PENDING"},
    )


def _run_with_fake(monkeypatch):
    import netops_lens.pipeline as pipeline_module

    calls: list = []
    canned = _full_report()

    def _fake(request, **kwargs):
        calls.append((request, kwargs))
        return canned

    monkeypatch.setattr(pipeline_module, "run_assessment_pipeline", _fake)
    at = AppTest.from_file(APP_PATH)
    at.run()
    at.sidebar.button[0].click().run()
    assert at.exception == [], [str(e) for e in at.exception]
    assert len(calls) == 1
    return at, calls, canned


def _frame_cells(frames: list) -> list[str]:
    """Every dataframe cell as a string (``in`` on a 2D array is row-wise)."""
    return [
        str(cell)
        for frame in frames
        for row in frame.astype(str).values.tolist()
        for cell in row
    ]


def _click_button(at: AppTest, label: str) -> None:
    matches = [button for button in at.button if button.label == label]
    assert matches, f"button {label!r} not rendered"
    matches[0].click().run()
    assert at.exception == [], [str(e) for e in at.exception]


def test_render_investigation_shows_narrative_and_activity():
    at = AppTest.from_file(APP_PATH)
    at.session_state["report"] = _full_report()
    at.run()
    assert at.exception == [], [str(e) for e in at.exception]
    texts = _texts(at)
    assert any("regressed in the proposed snapshot" in text for text in texts)
    assert any("trace_flow" in text for text in texts)
    assert any("ev-0001" in text for text in texts)
    assert any("does not change the verdict" in text for text in texts)


def test_render_investigation_absent_when_not_run():
    at = AppTest.from_file(APP_PATH)
    at.session_state["report"] = _canned_report()
    at.run()
    assert at.exception == [], [str(e) for e in at.exception]
    assert any(
        "Investigation was not run for this assessment." in text
        for text in _texts(at)
    )


def test_render_candidates_shows_verified_candidate():
    at = AppTest.from_file(APP_PATH)
    at.session_state["report"] = _full_report()
    at.run()
    assert at.exception == [], [str(e) for e in at.exception]
    texts = _texts(at)
    assert any("Candidate c-01" in text for text in texts)
    frames = [df.value for df in at.dataframe]
    assert frames, "operations must render as a table"
    cells = _frame_cells(frames)
    assert any("add_static_route" in cell for cell in cells)
    assert any("10.0.12.2" in cell for cell in cells), (
        "operation parameters must be visible"
    )
    assert any(
        "ip route 198.51.100.0 255.255.255.0 10.0.12.2" in text for text in texts
    ), "diff lines must render"
    assert "Verification: VERIFIED" in [s.value for s in at.success]
    assert any("candidate_health" in text for text in texts)
    assert any("reachability_restored" in text for text in texts)


def test_non_verified_candidate_has_no_decision_buttons():
    at = AppTest.from_file(APP_PATH)
    at.session_state["report"] = _full_report()
    at.run()
    assert at.exception == [], [str(e) for e in at.exception]
    assert "Verification: REJECTED" in [e.value for e in at.error]
    labels = [button.label for button in at.button]
    assert "Approve c-01" in labels
    assert "Reject c-01" in labels
    assert "Approve c-02" not in labels
    assert "Reject c-02" not in labels
    assert any("Human decision requires VERIFIED status." in text for text in _texts(at))


def test_approve_flow_updates_decision_without_rerun(monkeypatch):
    at, calls, _ = _run_with_fake(monkeypatch)
    assert at.session_state["report"].human_decision == {
        "c-01": "PENDING",
        "c-02": "PENDING",
    }
    _click_button(at, "Approve c-01")
    assert at.session_state["report"].human_decision == {
        "c-01": "APPROVED",
        "c-02": "PENDING",
    }
    assert len(calls) == 1, "approving must not rerun the pipeline"


def test_reject_flow_updates_decision(monkeypatch):
    at, calls, _ = _run_with_fake(monkeypatch)
    _click_button(at, "Reject c-01")
    assert at.session_state["report"].human_decision == {
        "c-01": "REJECTED",
        "c-02": "PENDING",
    }
    assert len(calls) == 1, "rejecting must not rerun the pipeline"


@pytest.mark.parametrize(
    ("op", "expected"),
    [
        (
            AddStaticRoute(
                op="add_static_route",
                node="r1",
                prefix="198.51.100.0/24",
                next_hop="10.0.12.2",
            ),
            "add_static_route r1 198.51.100.0/24 via 10.0.12.2",
        ),
        (
            RemoveStaticRoute(
                op="remove_static_route",
                node="r1",
                prefix="198.51.100.0/24",
                next_hop="10.0.12.2",
            ),
            "remove_static_route r1 198.51.100.0/24 via 10.0.12.2",
        ),
        (
            AclPermit(
                op="acl_permit",
                node="r1",
                acl="DB-FILTER",
                sequence_number=10,
                src="192.0.2.0/24",
                dst="198.51.100.0/24",
                protocol="tcp",
                dst_port=1433,
            ),
            "acl_permit r1 DB-FILTER seq 10 192.0.2.0/24 198.51.100.0/24 tcp 1433",
        ),
        (
            AclDeny(
                op="acl_deny",
                node="r1",
                acl="DB-FILTER",
                sequence_number=20,
                src="192.0.2.0/24",
                dst="198.51.100.0/24",
                protocol="tcp",
                dst_port=22,
            ),
            "acl_deny r1 DB-FILTER seq 20 192.0.2.0/24 198.51.100.0/24 tcp 22",
        ),
        (
            RemoveAclLine(
                op="remove_acl_line",
                node="r1",
                acl="DB-FILTER",
                sequence_number=10,
                expected_rule={
                    "action": "deny",
                    "src": "192.0.2.0/24",
                    "dst": "198.51.100.0/24",
                    "protocol": "tcp",
                    "dst_port": 1433,
                },
            ),
            "remove_acl_line r1 DB-FILTER seq 10 "
            "expect deny 192.0.2.0/24 198.51.100.0/24 tcp 1433",
        ),
    ],
)
def test_describe_op_covers_all_variants(op, expected):
    assert app.describe_op(op) == expected
    assert "AclAction" not in app.describe_op(op)


def test_candidate_diff_text_exact():
    application = ApplicationResult(
        candidate_id="c-01",
        applied=True,
        changed_files=("configs/r1.cfg",),
        diff=(
            FileDiff(
                file="configs/r1.cfg",
                removed=("ip route 10.9.9.0 255.255.255.0 192.0.2.1",),
                added=(
                    "ip route 10.9.9.0 255.255.255.0 192.0.2.2",
                    "ip route 10.9.9.0 255.255.255.0 192.0.2.3",
                ),
            ),
        ),
        reasons=(),
    )
    assert app.candidate_diff_text(application) == (
        "configs/r1.cfg\n"
        "- ip route 10.9.9.0 255.255.255.0 192.0.2.1\n"
        "+ ip route 10.9.9.0 255.255.255.0 192.0.2.2\n"
        "+ ip route 10.9.9.0 255.255.255.0 192.0.2.3\n"
    )


def test_download_button_only_for_verified_candidate():
    at = AppTest.from_file(APP_PATH)
    at.session_state["report"] = _full_report()
    at.run()
    assert at.exception == [], [str(e) for e in at.exception]
    labels = [button.label for button in at.download_button]
    assert "Download diff c-01" in labels
    assert "Download diff c-02" not in labels


def _real_pipeline_wrapper(monkeypatch, answers, candidates):
    """Patch the pipeline seam with a wrapper around the REAL pipeline.

    The wrapper injects a fake Batfish client and a canned Stage B while
    passing through the app's on_progress/on_warning kwargs, so the run
    exercises production Stage A, patching, Stage C, cleanup, and
    reporting with zero Batfish or Muse contact.
    """
    import netops_lens.pipeline as pipeline_module
    from netops_lens.models import InvestigationResult
    from tests.test_pipeline import PipeFake

    real_pipeline = pipeline_module.run_assessment_pipeline
    calls: list = []

    def _canned_stage_b(*args, **kwargs):
        return InvestigationResult(
            narrative="test investigation",
            candidates=candidates,
            tool_activity=[],
        )

    def _wrapper(request, **kwargs):
        calls.append(request)
        assert callable(kwargs.get("on_progress"))
        assert callable(kwargs.get("on_warning"))
        return real_pipeline(
            request,
            client_factory=lambda host, network: PipeFake(answers=answers),
            stage_b=_canned_stage_b,
            on_progress=kwargs.get("on_progress"),
            on_warning=kwargs.get("on_warning"),
        )

    monkeypatch.setattr(pipeline_module, "run_assessment_pipeline", _wrapper)
    return calls


def _run_scenario(at: AppTest, scenario: str):
    at.run()
    assert at.exception == [], [str(e) for e in at.exception]
    at.sidebar.selectbox[0].set_value(scenario).run()
    at.sidebar.button[0].click().run()
    assert at.exception == [], [str(e) for e in at.exception]


def test_scenario_healthy_renders_no_regression(monkeypatch):
    from tests.test_pipeline import PipeFake  # noqa: F401 (used via wrapper)

    answers = {
        ("traceroute", "healthy-baseline"): [trace_row("ACCEPTED")],
        ("traceroute", "healthy-proposed"): [trace_row("ACCEPTED")],
    }
    calls = _real_pipeline_wrapper(monkeypatch, answers, [])
    at = AppTest.from_file(APP_PATH)
    _run_scenario(at, "healthy")
    assert len(calls) == 1 and calls[0].scenario == "healthy"
    assert "Verdict: NO_REGRESSION_DETECTED" in [s.value for s in at.success]
    texts = _texts(at)
    assert any("untested traffic" in text for text in texts)
    assert any("No candidates were proposed." in text for text in texts)
    labels = [button.label for button in at.button] + [
        button.label for button in at.download_button
    ]
    assert not any(
        word in label for label in labels for word in ("Approve", "Reject", "Download")
    )
    report = at.session_state["report"]
    assert report.assessment.verdict == "NO_REGRESSION_DETECTED"


def test_scenario_removed_route_renders_verified_repair(monkeypatch):
    from tests.test_pipeline import PipeFake  # noqa: F401 (used via wrapper)
    from tests.test_pipeline import _cand_name, _route_candidate, _stage_a_answers

    tag = "removed_route"
    answers = dict(_stage_a_answers(tag))
    snap = _cand_name(tag, "c-01")
    answers[("traceroute", snap)] = [trace_row("ACCEPTED")]
    answers[("differentialReachability", snap)] = [
        differential_row("ACCEPTED", "ACCEPTED")
    ]
    calls = _real_pipeline_wrapper(monkeypatch, answers, [_route_candidate()])
    at = AppTest.from_file(APP_PATH)
    _run_scenario(at, tag)
    assert len(calls) == 1 and calls[0].scenario == tag
    assert "Verdict: REGRESSION_DETECTED" in [e.value for e in at.error]
    assert "Verification: VERIFIED" in [s.value for s in at.success]
    assert "Approve c-01" in [button.label for button in at.button]
    assert "Download diff c-01" in [button.label for button in at.download_button]
    report = at.session_state["report"]
    assert report.assessment.verdict == "REGRESSION_DETECTED"
    assert report.verifications[0].status == "VERIFIED"


def test_scenario_acl_blocks_db_renders_verified_repair(monkeypatch):
    from tests.test_pipeline import PipeFake  # noqa: F401 (used via wrapper)
    from tests.test_pipeline import _cand_name

    tag = "acl_blocks_db"
    flow_1433 = flow_dict(proto="TCP", dport=1433)
    flow_22 = flow_dict(proto="TCP", dport=22)
    answers = {
        ("traceroute", f"{tag}-baseline"): [
            trace_row("ACCEPTED", flow=flow_1433),
            trace_row("DENIED_IN", flow=flow_22),
        ],
        ("traceroute", f"{tag}-proposed"): [
            trace_row("DENIED_IN", flow=flow_1433),
            trace_row("DENIED_IN", flow=flow_22),
        ],
        ("differentialReachability", f"{tag}-proposed"): [
            differential_row("DENIED_IN", "ACCEPTED", flow=flow_1433),
            differential_row("DENIED_IN", "DENIED_IN", flow=flow_22),
        ],
    }
    snap = _cand_name(tag, "c-01")
    answers[("traceroute", snap)] = [
        trace_row("ACCEPTED", flow=flow_1433),
        trace_row("DENIED_IN", flow=flow_22),
    ]
    answers[("differentialReachability", snap)] = [
        differential_row("ACCEPTED", "ACCEPTED", flow=flow_1433),
        differential_row("DENIED_IN", "DENIED_IN", flow=flow_22),
    ]
    candidate = CandidatePatch(
        candidate_id="c-01",
        rationale="restore the authorized DB port",
        operations=[
            {
                "op": "remove_acl_line",
                "node": "r1",
                "acl": "DB-FILTER",
                "sequence_number": 10,
                "expected_rule": {
                    "action": "deny",
                    "src": "192.0.2.0/24",
                    "dst": "198.51.100.0/24",
                    "protocol": "tcp",
                    "dst_port": 1433,
                },
            },
            {
                "op": "acl_permit",
                "node": "r1",
                "acl": "DB-FILTER",
                "sequence_number": 10,
                "src": "192.0.2.0/24",
                "dst": "198.51.100.0/24",
                "protocol": "tcp",
                "dst_port": 1433,
            },
        ],
        target_flow_ids=["app-to-db-authorized"],
    )
    calls = _real_pipeline_wrapper(monkeypatch, answers, [candidate])
    at = AppTest.from_file(APP_PATH)
    _run_scenario(at, tag)
    assert len(calls) == 1 and calls[0].scenario == tag
    assert "Verdict: REGRESSION_DETECTED" in [e.value for e in at.error]
    assert "Verification: VERIFIED" in [s.value for s in at.success]
    cells = _frame_cells([df.value for df in at.dataframe])
    assert any("REGRESSION" in cell for cell in cells)
    assert any("NO_CHANGE_OK" in cell for cell in cells)
    assert "Approve c-01" in [button.label for button in at.button]
    report = at.session_state["report"]
    assert report.assessment.verdict == "REGRESSION_DETECTED"
    assert report.verifications[0].status == "VERIFIED"


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
