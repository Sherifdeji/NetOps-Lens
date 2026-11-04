"""Reusable pipeline boundary tests: no I/O, fresh context, isolation.

The pipeline (``run_assessment_pipeline``) is the backend entry point the
CLI wraps today and Streamlit will call in Phase 5.2. These tests prove the
contract: a complete serializable ``Report`` with all decisions ``PENDING``,
silence on stdout/stderr, no stdin prompts, no process exit, a fresh
execution context per call, and guaranteed cleanup. Fakes only; no Muse
calls, no Batfish.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from netops_lens import cli
from netops_lens.batfish_client import BatfishError
from netops_lens.intent import IntentError
from netops_lens.models import (
    ApplicationResult,
    AssessmentResult,
    CandidatePatch,
    FileDiff,
    InvestigationResult,
    Report,
    VerificationCheck,
    VerificationResult,
)
from netops_lens.pipeline import (
    AssessmentRequest,
    PipelineConnectionError,
    run_assessment_pipeline,
)
from netops_lens.report import ReportError, apply_human_decisions
from tests._fakes import FakeClient, differential_row, trace_row

START = "@enter(r1[GigabitEthernet0/1])"
INTENT_YAML = """\
version: 1
description: pipeline test
must_reach:
  - id: app-to-db-icmp
    src: "192.0.2.10"
    dst: "198.51.100.1"
    protocol: ICMP
    start_location: "@enter(r1[GigabitEthernet0/1])"
must_not_reach: []
"""

R1_MINIMAL = "hostname r1\n!\nend\n"


class PipeFake(FakeClient):
    """FakeClient plus the BatfishClient lifecycle surface the pipeline drives."""

    def __init__(self, *args, network="run-net-abc123", init_fail=(), delete_fail=(), **kwargs):
        super().__init__(*args, **kwargs)
        self._network = network
        self._registered = set()
        self.init_calls: list[dict] = []
        self.deleted: list[str] = []
        self.networks_deleted: list[str] = []
        self.init_fail = set(init_fail)
        self.delete_fail = set(delete_fail)

    def connect(self):
        return None

    @property
    def network(self):
        return self._network

    def delete_network(self):
        self.networks_deleted.append(self._network)
        from netops_lens.batfish_client import BatfishError as _BErr

        if self._network in self.delete_fail:
            raise _BErr("fake network delete failure")

    def init_snapshot(self, path, name, *, overwrite=True):
        self.init_calls.append({"path": str(path), "name": name, "overwrite": overwrite})
        if name in self.init_fail:
            raise BatfishError(f"fake init failure on {name}")
        return name

    def register_candidate_snapshot(self, name):
        from netops_lens.batfish_client import is_candidate_snapshot_name

        if not is_candidate_snapshot_name(name):
            raise BatfishError(f"refusing to register non-candidate snapshot {name!r}")
        self._registered.add(name)

    def is_registered_candidate(self, name):
        return name in self._registered

    def delete_snapshot(self, name):
        self.deleted.append(name)
        if name in self.delete_fail:
            raise BatfishError(f"fake delete failure on {name}")


def _route_candidate(candidate_id="c-01", **overrides) -> CandidatePatch:
    fields = {
        "op": "add_static_route",
        "node": "r1",
        "prefix": "198.51.100.0/24",
        "next_hop": "10.0.12.2",
    }
    fields.update(overrides)
    return CandidatePatch(
        candidate_id=candidate_id,
        rationale="test route",
        operations=[fields],
        target_flow_ids=["app-to-db-icmp"],
    )


def _deny_candidate(candidate_id="c-02") -> CandidatePatch:
    return CandidatePatch(
        candidate_id=candidate_id,
        rationale="bad shape",
        operations=[
            {
                "op": "acl_deny",
                "node": "r1",
                "acl": "DB-FILTER",
                "sequence_number": 20,
                "src": "192.0.2.0/24",
                "dst": "198.51.100.0/24",
                "protocol": "tcp",
                "dst_port": 22,
            }
        ],
        target_flow_ids=["app-to-db-icmp"],
    )


def _write_tree(root: Path) -> tuple[Path, Path, Path]:
    base = root / "base"
    prop = root / "proposed"
    (prop / "configs").mkdir(parents=True)
    (prop / "configs" / "r1.cfg").write_text(R1_MINIMAL)
    base.mkdir(parents=True)
    intent = root / "intent.yaml"
    intent.write_text(INTENT_YAML)
    return base, prop, intent


def _stage_a_answers(tag: str) -> dict:
    return {
        ("traceroute", f"{tag}-baseline"): [trace_row("ACCEPTED")],
        ("traceroute", f"{tag}-proposed"): [trace_row("NO_ROUTE")],
        ("differentialReachability", f"{tag}-proposed"): [
            differential_row("NO_ROUTE", "ACCEPTED")
        ],
    }


def _canned(candidates: list) -> object:
    def _investigation(*args, **kwargs):
        return InvestigationResult(narrative="test", candidates=candidates, tool_activity=[])

    return _investigation


def _request(base: Path, prop: Path, intent: Path, **overrides) -> AssessmentRequest:
    fields = {
        "baseline": str(base),
        "proposed": str(prop),
        "intent": str(intent),
    }
    fields.update(overrides)
    return AssessmentRequest(**fields)


def _run_pipeline(tmp_path, fake, candidates, name="case", **kw) -> Report:
    base, prop, intent = _write_tree(tmp_path / name)
    request = _request(base, prop, intent)
    return run_assessment_pipeline(
        request,
        settings=kw.pop("settings", None) or _settings(),
        stage_b=_canned(candidates),
        client_factory=lambda host, network: fake,
        **kw,
    )


def _settings():
    from netops_lens.config import Settings

    return Settings()


def _cand_name(tag, candidate_id):
    from netops_lens.batfish_client import candidate_snapshot_name

    return candidate_snapshot_name(tag, candidate_id)


# --- reusable API ---------------------------------------------------------


def test_returns_complete_report_with_pending_decisions(tmp_path, capsys):
    tag = "manual"
    snap = _cand_name(tag, "c-01")
    answers = dict(_stage_a_answers(tag))
    answers[("traceroute", snap)] = [trace_row("ACCEPTED")]
    answers[("differentialReachability", snap)] = [differential_row("ACCEPTED", "ACCEPTED")]
    fake = PipeFake(answers=answers)
    report = _run_pipeline(tmp_path, fake, [_route_candidate()])
    assert report.assessment.verdict == "REGRESSION_DETECTED"
    assert report.investigation is not None and report.investigation.narrative == "test"
    assert [a.candidate_id for a in report.applications] == ["c-01"]
    assert report.applications[0].applied is True
    assert [v.candidate_id for v in report.verifications] == ["c-01"]
    assert report.verifications[0].status == "VERIFIED"
    assert report.human_decision == {"c-01": "PENDING"}
    assert report.evidence_index, "the run evidence index travels with the report"
    # The report is JSON-serializable (the Streamlit-safe handoff shape).
    json.dumps(report.model_dump(mode="json"))
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_pipeline_never_prompts_or_exits(tmp_path, monkeypatch):
    tag = "manual"
    snap = _cand_name(tag, "c-01")
    answers = dict(_stage_a_answers(tag))
    answers[("traceroute", snap)] = [trace_row("ACCEPTED")]
    answers[("differentialReachability", snap)] = [differential_row("ACCEPTED", "ACCEPTED")]
    fake = PipeFake(answers=answers)

    def _boom(*args, **kwargs):  # pragma: no cover - must never run
        raise AssertionError("pipeline must not read stdin")

    monkeypatch.setattr("builtins.input", _boom)
    report = _run_pipeline(tmp_path, fake, [_route_candidate()])
    assert report.verifications[0].status == "VERIFIED"
    assert report.human_decision == {"c-01": "PENDING"}


def test_no_investigate_skips_stage_b_and_c(tmp_path):
    fake = PipeFake(answers=_stage_a_answers("manual"))
    base, prop, intent = _write_tree(tmp_path / "case")
    request = _request(base, prop, intent, no_investigate=True)
    report = run_assessment_pipeline(
        request,
        settings=_settings(),
        stage_b=_canned([_route_candidate()]),
        client_factory=lambda host, network: fake,
    )
    assert report.assessment.verdict == "REGRESSION_DETECTED"
    assert report.investigation is None
    assert report.applications == []
    assert report.verifications == []
    assert report.human_decision == {}
    assert [c["name"] for c in fake.init_calls if "candidate" in c["name"]] == []


def test_mixed_outcomes_all_start_pending(tmp_path):
    tag = "manual"
    snap = _cand_name(tag, "c-01")
    answers = dict(_stage_a_answers(tag))
    answers[("traceroute", snap)] = [trace_row("ACCEPTED")]
    answers[("differentialReachability", snap)] = [differential_row("ACCEPTED", "ACCEPTED")]
    fake = PipeFake(answers=answers)
    report = _run_pipeline(tmp_path, fake, [_route_candidate("c-01"), _deny_candidate("c-02")])
    by_id = {v.candidate_id: v for v in report.verifications}
    assert by_id["c-01"].status == "VERIFIED"
    assert by_id["c-02"].status == "UNVERIFIABLE"
    assert report.human_decision == {"c-01": "PENDING", "c-02": "PENDING"}


# --- execution isolation --------------------------------------------------


def test_sequential_runs_create_distinct_contexts(tmp_path):
    seen_networks: list[str] = []
    seen_clients: list[object] = []

    def factory(host, network):
        seen_networks.append(network)
        client = PipeFake(answers=_stage_a_answers("manual"), network=network)
        seen_clients.append(client)
        return client

    first_done: dict = {}

    def run_case(name):
        base, prop, intent = _write_tree(tmp_path / name)
        return run_assessment_pipeline(
            _request(base, prop, intent),
            settings=_settings(),
            stage_b=_canned([]),
            client_factory=factory,
        )

    first = run_case("first")
    first_done["dump"] = first.model_dump_json()
    second = run_case("second")

    assert len(seen_networks) == 2
    assert seen_networks[0] != seen_networks[1]
    assert all(n.startswith("netops-lens-lab-manual-") for n in seen_networks)
    assert seen_clients[0] is not seen_clients[1]
    assert second.assessment.verdict == "REGRESSION_DETECTED"
    # The earlier report is stable: nothing from the second run leaks into it.
    assert first.model_dump_json() == first_done["dump"]
    assert set(second.evidence_index) == set(first.evidence_index)
    assert second.evidence_index is not first.evidence_index


def test_failed_connect_still_cleans_up(tmp_path):
    deleted: list[str] = []

    class ConnectFail(PipeFake):
        def connect(self):
            raise BatfishError("set_network blew up halfway")

        def delete_network(self):
            deleted.append(self.network)

    base, prop, intent = _write_tree(tmp_path / "case")
    with pytest.raises(PipelineConnectionError):
        run_assessment_pipeline(
            _request(base, prop, intent),
            settings=_settings(),
            stage_b=_canned([]),
            client_factory=lambda host, network: ConnectFail(network=network),
        )
    assert len(deleted) == 1
    assert deleted[0].startswith("netops-lens-lab-manual-")


def test_protected_network_is_never_deleted(tmp_path):
    deleted: list[str] = []

    class SharedNetwork(PipeFake):
        @property
        def network(self):
            return "netops-lens-lab"

        def delete_network(self):  # pragma: no cover - must never run
            deleted.append(self.network)
            raise AssertionError("protected network must never be deleted")

    base, prop, intent = _write_tree(tmp_path / "case")
    report = run_assessment_pipeline(
        _request(base, prop, intent),
        settings=_settings(),
        stage_b=_canned([]),
        client_factory=lambda host, network: SharedNetwork(
            answers=_stage_a_answers("manual"), network=network
        ),
    )
    assert report.assessment.verdict == "REGRESSION_DETECTED"
    assert deleted == []


def test_cleanup_warnings_forwarded_not_printed(tmp_path, capsys):
    tag = "manual"
    snap = _cand_name(tag, "c-01")
    answers = dict(_stage_a_answers(tag))
    answers[("traceroute", snap)] = [trace_row("ACCEPTED")]
    answers[("differentialReachability", snap)] = [differential_row("ACCEPTED", "ACCEPTED")]

    warnings: list[str] = []
    report = _run_pipeline(
        tmp_path,
        PipeFake(answers=answers, delete_fail={snap}),
        [_route_candidate()],
        on_warning=warnings.append,
    )
    assert report.verifications[0].status == "VERIFIED"
    assert any("cleanup failed" in w for w in warnings)
    assert capsys.readouterr().err == ""

    report2 = _run_pipeline(
        tmp_path,
        PipeFake(answers=answers, delete_fail={snap}),
        [_route_candidate()],
        name="silent",
    )
    assert report2.verifications[0].status == "VERIFIED"
    assert capsys.readouterr().err == ""


def test_input_errors_raise_before_any_assessment(tmp_path):
    base, prop, intent = _write_tree(tmp_path / "case")
    with pytest.raises(IntentError, match="unknown scenario"):
        run_assessment_pipeline(
            AssessmentRequest(scenario="nope"),
            settings=_settings(),
            client_factory=lambda host, network: PipeFake(),
        )
    with pytest.raises(IntentError, match="provide --scenario"):
        run_assessment_pipeline(
            AssessmentRequest(baseline=str(base), proposed=str(prop)),
            settings=_settings(),
            client_factory=lambda host, network: PipeFake(),
        )
    with pytest.raises(IntentError, match="intent file not found"):
        run_assessment_pipeline(
            _request(base, prop, Path("missing-intent.yaml")),
            settings=_settings(),
            client_factory=lambda host, network: PipeFake(),
        )


# --- report decision helper -------------------------------------------------


def _decided_report(status: str = "VERIFIED") -> Report:
    application = ApplicationResult(
        candidate_id="c-01",
        applied=True,
        changed_files=("configs/r1.cfg",),
        diff=(FileDiff(file="configs/r1.cfg", removed=(), added=("x",)),),
        reasons=(),
    )
    check = VerificationCheck(
        name="candidate_health", outcome="pass", detail="ok", evidence_ids=("ev-0001",)
    )
    verification = VerificationResult(
        candidate_id="c-01",
        status=status,  # type: ignore[arg-type]
        reasons=(),
        checks=(check,),
        evidence_ids=("ev-0001",),
        candidate_snapshot="manual-candidate-c-01",
    )
    return Report(
        assessment=AssessmentResult(verdict="REGRESSION_DETECTED"),
        investigation=None,
        applications=[application],
        verifications=[verification],
        human_decision={"c-01": "PENDING"},
        evidence_index={},
        traces=[],
    )


def test_apply_human_decisions_records_approved_for_verified():
    report = _decided_report("VERIFIED")
    updated = apply_human_decisions(report, {"c-01": "APPROVED"})
    assert updated.human_decision == {"c-01": "APPROVED"}
    assert report.human_decision == {"c-01": "PENDING"}
    assert updated.assessment.verdict == "REGRESSION_DETECTED"


def test_apply_human_decisions_rejects_approved_for_unverified():
    for status in ("REJECTED", "UNVERIFIABLE"):
        with pytest.raises(ReportError, match="illegal"):
            apply_human_decisions(_decided_report(status), {"c-01": "APPROVED"})


def test_apply_human_decisions_rejects_key_mismatch():
    with pytest.raises(ReportError, match="mismatch"):
        apply_human_decisions(_decided_report(), {})
    with pytest.raises(ReportError, match="mismatch"):
        apply_human_decisions(_decided_report(), {"c-01": "PENDING", "c-09": "PENDING"})


def test_apply_human_decisions_empty_report_takes_empty_map():
    report = Report(
        assessment=AssessmentResult(verdict="NO_REGRESSION_DETECTED"),
        human_decision={},
    )
    assert apply_human_decisions(report, {}).human_decision == {}


# --- CLI stays a thin wrapper -------------------------------------------------


def test_cli_input_error_exit_code(tmp_path, capsys):
    argv = ["assess", "--scenario", "nope"]
    assert cli.run_assess(cli.build_parser().parse_args(argv)) == 1
    assert "input error" in capsys.readouterr().err


def test_cli_missing_intent_exit_code(tmp_path, capsys):
    base = tmp_path / "base"
    base.mkdir()
    argv = [
        "assess",
        "--baseline",
        str(base),
        "--proposed",
        str(base),
        "--intent",
        str(tmp_path / "missing.yaml"),
    ]
    assert cli.run_assess(cli.build_parser().parse_args(argv)) == 1
    assert "input error" in capsys.readouterr().err
