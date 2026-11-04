"""CLI Stage C orchestration tests (no live Batfish, no model calls).

A lifecycle-recording fake stands in for Batfish; ``run_stage_b`` is
stubbed with canned investigations; patch application and verification are
the real deterministic implementations running against tmp snapshot trees.
"""

from __future__ import annotations

import json
from pathlib import Path

from netops_lens import cli, pipeline
from netops_lens.batfish_client import BatfishError
from netops_lens.models import (
    ApplicationResult,
    CandidatePatch,
    FileDiff,
    InvestigationResult,
    VerificationCheck,
    VerificationResult,
)
from tests._fakes import FakeClient, differential_row, flow_dict, trace_row

START = "@enter(r1[GigabitEthernet0/1])"
INTENT_YAML = """\
version: 1
description: stage c test
must_reach:
  - id: app-to-db-icmp
    src: "192.0.2.10"
    dst: "198.51.100.1"
    protocol: ICMP
    start_location: "@enter(r1[GigabitEthernet0/1])"
must_not_reach: []
"""

R1_MINIMAL = "hostname r1\n!\nend\n"


class StageCFake(FakeClient):
    """FakeClient plus the BatfishClient lifecycle surface the CLI drives."""

    def __init__(
        self,
        *args,
        network="run-net-abc123",
        init_fail=(),
        delete_fail=(),
        no_register=False,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self._network = network
        self._registered = set()
        self._no_register = no_register
        self.init_calls: list[dict] = []
        self.deleted: list[str] = []
        self.networks_deleted: list[str] = []
        self.events: list[tuple[str, str]] = []
        self.init_fail = set(init_fail)
        self.delete_fail = set(delete_fail)

    def connect(self):
        return None

    @property
    def network(self):
        return self._network

    def delete_network(self):
        self.networks_deleted.append(self._network)
        self.events.append(("network", self._network))

    def init_snapshot(self, path, name, *, overwrite=True):
        self.init_calls.append({"path": str(path), "name": name, "overwrite": overwrite})
        if name in self.init_fail:
            raise BatfishError(f"fake init failure on {name}")
        return name

    def register_candidate_snapshot(self, name):
        from netops_lens.batfish_client import is_candidate_snapshot_name

        if not is_candidate_snapshot_name(name):
            raise BatfishError(f"refusing to register non-candidate snapshot {name!r}")
        if not self._no_register:
            self._registered.add(name)

    def is_registered_candidate(self, name):
        return name in self._registered

    def delete_snapshot(self, name):
        self.deleted.append(name)
        self.events.append(("snapshot", name))
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


def _args(base: Path, prop: Path, intent: Path, **flags) -> object:
    argv = [
        "assess",
        "--baseline", str(base),
        "--proposed", str(prop),
        "--intent", str(intent),
    ]
    namespace = cli.build_parser().parse_args(argv)
    for key, value in flags.items():
        setattr(namespace, key, value)
    return namespace


def _stage_a_answers(tag: str) -> dict:
    return {
        ("traceroute", f"{tag}-baseline"): [trace_row("ACCEPTED")],
        ("traceroute", f"{tag}-proposed"): [trace_row("NO_ROUTE")],
        ("differentialReachability", f"{tag}-proposed"): [
            differential_row("NO_ROUTE", "ACCEPTED")
        ],
    }


def _run(monkeypatch, tmp_path, fake, candidates, name="snapshots", **flags):
    base, prop, intent = _write_tree(tmp_path / name)

    def _investigation(*args, **kwargs):
        return InvestigationResult(narrative="test", candidates=candidates, tool_activity=[])

    monkeypatch.setattr(cli, "BatfishClient", lambda host, network: fake)
    monkeypatch.setattr(cli, "run_stage_b", _investigation)
    monkeypatch.setattr(pipeline, "REPO_ROOT", tmp_path)
    return cli.run_assess(_args(base, prop, intent, **flags))


def _cand_name(tag, candidate_id):
    from netops_lens.batfish_client import candidate_snapshot_name

    return candidate_snapshot_name(tag, candidate_id)


def test_stage_c_skipped_without_candidates(monkeypatch, tmp_path, capsys):
    fake = StageCFake(answers=_stage_a_answers("manual"))
    code = _run(monkeypatch, tmp_path, fake, [], json=True)
    assert code == 0
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["applications"] == []
    assert payload["verifications"] == []
    assert payload["human_decision"] == {}
    assert "manual-candidate" not in out
    assert [c["name"] for c in fake.init_calls if "candidate" in c["name"]] == []


def test_stage_c_skipped_for_no_regression(monkeypatch, tmp_path, capsys):
    answers = dict(_stage_a_answers("manual"))
    answers[("traceroute", "manual-proposed")] = [trace_row("ACCEPTED")]
    answers[("differentialReachability", "manual-proposed")] = [
        differential_row("ACCEPTED", "ACCEPTED")
    ]
    fake = StageCFake(answers=answers)
    code = _run(monkeypatch, tmp_path, fake, [_route_candidate()], json=True)
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["assessment"]["verdict"] == "NO_REGRESSION_DETECTED"
    assert payload["applications"] == []
    assert [c["name"] for c in fake.init_calls if "candidate" in c["name"]] == []


def test_stage_c_skipped_for_inconclusive_and_no_investigate(monkeypatch, tmp_path, capsys):
    answers = dict(_stage_a_answers("manual"))
    answers[("traceroute", "manual-proposed")] = []
    fake = StageCFake(answers=answers)
    code = _run(monkeypatch, tmp_path, fake, [_route_candidate()], json=True)
    assert code == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["assessment"]["verdict"] == "INCONCLUSIVE"
    assert payload["applications"] == []

    fake2 = StageCFake(answers=_stage_a_answers("manual"))
    code = _run(
        monkeypatch, tmp_path, fake2, [_route_candidate()],
        name="snapshots2", no_investigate=True,
    )
    assert code == 0
    assert [c["name"] for c in fake2.init_calls if "candidate" in c["name"]] == []


def test_successful_candidate_verified_and_cleaned_up(monkeypatch, tmp_path, capsys):
    tag = "manual"
    snap = _cand_name(tag, "c-01")
    answers = dict(_stage_a_answers(tag))
    answers[("traceroute", snap)] = [trace_row("ACCEPTED")]
    answers[("differentialReachability", snap)] = [differential_row("ACCEPTED", "ACCEPTED")]
    fake = StageCFake(answers=answers)
    code = _run(monkeypatch, tmp_path, fake, [_route_candidate()], json=True)
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["applications"][0]["candidate_id"] == "c-01"
    assert payload["applications"][0]["applied"] is True
    assert payload["verifications"][0]["status"] == "VERIFIED"
    assert payload["human_decision"] == {"c-01": "PENDING"}
    inits = [c for c in fake.init_calls if "candidate" in c["name"]]
    assert [(c["name"], c["overwrite"]) for c in inits] == [(snap, False)]
    assert snap in fake.deleted
    assert fake.networks_deleted == [fake.network]


def test_application_failure_needs_no_snapshot(monkeypatch, tmp_path, capsys):
    tag = "manual"
    snap = _cand_name(tag, "c-01")
    answers = dict(_stage_a_answers(tag))
    answers[("traceroute", snap)] = [trace_row("ACCEPTED")]
    answers[("differentialReachability", snap)] = [differential_row("ACCEPTED", "ACCEPTED")]
    fake = StageCFake(answers=answers)
    good = _route_candidate("c-01")
    bad = _deny_candidate("c-02")
    code = _run(monkeypatch, tmp_path, fake, [good, bad], json=True)
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    by_id = {a["candidate_id"]: a for a in payload["applications"]}
    assert by_id["c-02"]["applied"] is False
    ver_by_id = {v["candidate_id"]: v for v in payload["verifications"]}
    assert ver_by_id["c-02"]["status"] == "UNVERIFIABLE"
    assert ver_by_id["c-02"]["candidate_snapshot"] is None
    assert ver_by_id["c-01"]["status"] == "VERIFIED"
    assert all("manual-candidate-c-02" != c["name"] for c in fake.init_calls)


def test_init_failure_skips_register_verify_and_delete(monkeypatch, tmp_path, capsys):
    tag = "manual"
    snap = _cand_name(tag, "c-01")
    answers = dict(_stage_a_answers(tag))
    fake = StageCFake(answers=answers, init_fail={snap})
    code = _run(monkeypatch, tmp_path, fake, [_route_candidate()], json=True)
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["applications"][0]["applied"] is True
    ver = payload["verifications"][0]
    assert ver["status"] == "UNVERIFIABLE"
    assert ver["candidate_snapshot"] is None
    assert not fake.is_registered_candidate(snap)
    assert snap not in fake.deleted
    assert fake.asked("traceroute", snap) == 0


def test_name_collision_never_overwrites(monkeypatch, tmp_path, capsys):
    tag = "manual"
    snap = _cand_name(tag, "c-01")
    answers = dict(_stage_a_answers(tag))
    fake = StageCFake(answers=answers)
    fake._registered.add(snap)
    code = _run(monkeypatch, tmp_path, fake, [_route_candidate()], json=True)
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["verifications"][0]["status"] == "UNVERIFIABLE"
    assert all(c["name"] != snap for c in fake.init_calls)
    assert snap not in fake.deleted


def test_protected_name_collision_refused(monkeypatch, tmp_path, capsys):
    tag = "manual"
    answers = dict(_stage_a_answers(tag))
    fake = StageCFake(answers=answers)
    monkeypatch.setattr(
        pipeline, "candidate_snapshot_name", lambda tag, cid: "manual-proposed"
    )
    code = _run(monkeypatch, tmp_path, fake, [_route_candidate()], json=True)
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["verifications"][0]["status"] == "UNVERIFIABLE"
    # Base/proposed initialize normally; no candidate init may touch them.
    assert all(c["overwrite"] is True for c in fake.init_calls)


def test_unregistered_candidate_is_not_verified(monkeypatch, tmp_path, capsys):
    tag = "manual"
    snap = _cand_name(tag, "c-01")
    answers = dict(_stage_a_answers(tag))
    answers[("traceroute", snap)] = [trace_row("ACCEPTED")]
    answers[("differentialReachability", snap)] = [differential_row("ACCEPTED", "ACCEPTED")]
    fake = StageCFake(answers=answers, no_register=True)
    code = _run(monkeypatch, tmp_path, fake, [_route_candidate()], json=True)
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["verifications"][0]["status"] == "UNVERIFIABLE"
    assert fake.asked("traceroute", snap) == 0
    assert snap not in fake.deleted


def test_candidate_snapshot_deleted_after_each_outcome(monkeypatch, tmp_path, capsys):
    tag = "manual"
    good, bad, ugly = "c-01", "c-02", "c-03"
    snaps = {c: _cand_name(tag, c) for c in (good, bad, ugly)}
    answers = dict(_stage_a_answers(tag))
    answers[("traceroute", snaps[good])] = [trace_row("ACCEPTED")]
    answers[("differentialReachability", snaps[good])] = [differential_row("ACCEPTED", "ACCEPTED")]
    answers[("traceroute", snaps[bad])] = [trace_row("NO_ROUTE")]
    answers[("differentialReachability", snaps[bad])] = [differential_row("NO_ROUTE", "ACCEPTED")]
    answers[("traceroute", snaps[ugly])] = [trace_row("NO_ROUTE")]
    answers[("differentialReachability", snaps[ugly])] = []
    fake = StageCFake(answers=answers)
    code = _run(
        monkeypatch, tmp_path, fake,
        [_route_candidate(good), _route_candidate(bad), _route_candidate(ugly)],
        json=True,
    )
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    by_id = {v["candidate_id"]: v["status"] for v in payload["verifications"]}
    assert by_id == {good: "VERIFIED", bad: "REJECTED", ugly: "UNVERIFIABLE"}
    for snap in snaps.values():
        assert snap in fake.deleted
    assert [c["overwrite"] for c in fake.init_calls if "candidate" in c["name"]] == [False] * 3
    runs_root = tmp_path / "runs"
    leftovers = [p for p in runs_root.rglob("candidate-*")] if runs_root.exists() else []
    assert leftovers == []


def test_snapshot_deletion_failure_warns_but_preserves_result(monkeypatch, tmp_path, capsys):
    tag = "manual"
    snap = _cand_name(tag, "c-01")
    answers = dict(_stage_a_answers(tag))
    answers[("traceroute", snap)] = [trace_row("ACCEPTED")]
    answers[("differentialReachability", snap)] = [differential_row("ACCEPTED", "ACCEPTED")]
    fake = StageCFake(answers=answers, delete_fail={snap})
    code = _run(monkeypatch, tmp_path, fake, [_route_candidate()], json=True)
    assert code == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["verifications"][0]["status"] == "VERIFIED"
    assert "cleanup failed" in captured.err


def test_one_candidate_failure_does_not_stop_others(monkeypatch, tmp_path, capsys):
    tag = "manual"
    first = _cand_name(tag, "c-01")
    second = _cand_name(tag, "c-02")
    answers = dict(_stage_a_answers(tag))
    answers[("traceroute", second)] = [trace_row("ACCEPTED")]
    answers[("differentialReachability", second)] = [differential_row("ACCEPTED", "ACCEPTED")]
    fake = StageCFake(answers=answers, init_fail={first})
    code = _run(
        monkeypatch, tmp_path, fake, [_route_candidate("c-01"), _route_candidate("c-02")],
        json=True,
    )
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    by_id = {v["candidate_id"]: v for v in payload["verifications"]}
    assert by_id["c-01"]["status"] == "UNVERIFIABLE"
    assert by_id["c-01"]["candidate_snapshot"] is None
    assert by_id["c-02"]["status"] == "VERIFIED"


def test_candidate_b_starts_from_original_proposed(monkeypatch, tmp_path, capsys):
    tag = "manual"
    first = _cand_name(tag, "c-01")
    second = _cand_name(tag, "c-02")
    answers = dict(_stage_a_answers(tag))
    for snap in (first, second):
        answers[("traceroute", snap)] = [trace_row("ACCEPTED")]
        answers[("differentialReachability", snap)] = [differential_row("ACCEPTED", "ACCEPTED")]
    fake = StageCFake(answers=answers)
    code = _run(
        monkeypatch, tmp_path, fake,
        [_route_candidate("c-01", prefix="10.9.9.0/24"),
         _route_candidate("c-02", prefix="10.8.8.0/24")],
        json=True,
    )
    assert code == 0
    assert json.loads(capsys.readouterr().out)["verifications"][1]["status"] == "VERIFIED"
    assert fake.asked("traceroute", second) == 1


def test_verify_receives_canonical_candidate_ref(monkeypatch, tmp_path, capsys):
    tag = "manual"
    snap = _cand_name(tag, "c-01")
    answers = dict(_stage_a_answers(tag))
    answers[("traceroute", snap)] = [trace_row("ACCEPTED")]
    answers[("differentialReachability", snap)] = [differential_row("ACCEPTED", "ACCEPTED")]
    fake = StageCFake(answers=answers)
    seen = []
    real_verify = pipeline.verify_candidate

    def recording(*args, **kwargs):
        seen.append(kwargs["candidate_ref"])
        return real_verify(*args, **kwargs)

    monkeypatch.setattr(pipeline, "verify_candidate", recording)
    code = _run(monkeypatch, tmp_path, fake, [_route_candidate()], json=True)
    assert code == 0
    assert len(seen) == 1
    assert seen[0].name == snap
    assert seen[0].path.endswith("candidate-c-01")


PAIR_INTENT_YAML = """\
version: 1
description: improve-a-break-b
must_reach:
  - id: flow-a
    src: "192.0.2.10"
    dst: "198.51.100.1"
    protocol: ICMP
    start_location: "@enter(r1[GigabitEthernet0/1])"
  - id: flow-c
    src: "192.0.2.10"
    dst: "198.51.100.1"
    protocol: TCP
    dst_port: 1433
    start_location: "@enter(r1[GigabitEthernet0/1])"
must_not_reach:
  - id: flow-b
    src: "192.0.2.10"
    dst: "198.51.100.1"
    protocol: TCP
    dst_port: 22
    start_location: "@enter(r1[GigabitEthernet0/1])"
"""

_TCP22 = flow_dict(proto="TCP", dport=22)
_TCP1433 = flow_dict(proto="TCP", dport=1433)


def _pair_run(monkeypatch, tmp_path, answers, **flags):
    base, prop, _ = _write_tree(tmp_path / "pair")
    intent_path = tmp_path / "pair" / "pair-intent.yaml"
    intent_path.write_text(PAIR_INTENT_YAML)
    fake = StageCFake(answers=answers)

    def _investigation(*args, **kwargs):
        return InvestigationResult(
            narrative="t", candidates=[_route_candidate("c-01")], tool_activity=[]
        )

    monkeypatch.setattr(cli, "BatfishClient", lambda host, network: fake)
    monkeypatch.setattr(cli, "run_stage_b", _investigation)
    monkeypatch.setattr(pipeline, "REPO_ROOT", tmp_path)
    argv = ["assess", "--baseline", str(base), "--proposed", str(prop),
            "--intent", str(intent_path)]
    if flags.get("json"):
        argv.append("--json")
    assert cli.run_assess(cli.build_parser().parse_args(argv)) == 0
    return fake


def test_improve_one_break_another_is_rejected(monkeypatch, tmp_path, capsys):
    # Flow A is pre-existing-broken in Stage A and fixed by the candidate
    # (IMPROVEMENT over baseline); flow B is opened by the candidate
    # (REGRESSION over baseline). Flow C drives the REGRESSION_DETECTED
    # verdict and is repaired to its baseline state.
    tag = "manual"
    snap = _cand_name(tag, "c-01")
    answers = {
        ("traceroute", "manual-baseline"): [
            trace_row("NO_ROUTE"),
            trace_row("DENIED_IN", flow=_TCP22),
            trace_row("ACCEPTED", flow=_TCP1433),
        ],
        ("traceroute", "manual-proposed"): [
            trace_row("NO_ROUTE"),
            trace_row("DENIED_IN", flow=_TCP22),
            trace_row("NO_ROUTE", flow=_TCP1433),
        ],
        ("differentialReachability", "manual-proposed"): [
            differential_row("NO_ROUTE", "NO_ROUTE"),
            differential_row("DENIED_IN", "DENIED_IN", flow=_TCP22),
            differential_row("NO_ROUTE", "ACCEPTED", flow=_TCP1433),
        ],
        ("traceroute", snap): [
            trace_row("ACCEPTED"),
            trace_row("ACCEPTED", flow=_TCP22),
            trace_row("ACCEPTED", flow=_TCP1433),
        ],
        ("differentialReachability", snap): [
            differential_row("ACCEPTED", "NO_ROUTE"),
            differential_row("ACCEPTED", "DENIED_IN", flow=_TCP22),
            differential_row("ACCEPTED", "ACCEPTED", flow=_TCP1433),
        ],
    }
    _pair_run(monkeypatch, tmp_path, answers, json=True)
    payload = json.loads(capsys.readouterr().out)
    assert payload["assessment"]["verdict"] == "REGRESSION_DETECTED"
    ver = payload["verifications"][0]
    assert ver["status"] == "REJECTED"
    by_name = {c["name"]: c["outcome"] for c in ver["checks"]}
    assert by_name["intent:flow-a"] == "pass"
    assert by_name["no_regression:flow-a"] == "pass"
    assert by_name["intent:flow-b"] == "fail"
    assert by_name["no_regression:flow-b"] == "fail"
    assert by_name["no_regression:flow-c"] == "pass"


def _decisions(candidates, applications, verifications, **kwargs):
    params: dict = {"json_mode": False, "tty": True}
    params.update(kwargs)
    return cli._collect_decisions(candidates, applications, verifications, **params)


ADDED_ROUTE = "ip route 198.51.100.0 255.255.255.0 10.0.12.2"


def _verified_triplet(candidate_id="c-01"):
    candidate = _route_candidate(candidate_id)
    application = ApplicationResult(
        candidate_id=candidate_id,
        applied=True,
        changed_files=("configs/r1.cfg",),
        diff=(FileDiff(file="configs/r1.cfg", removed=(), added=(ADDED_ROUTE,)),),
        reasons=(),
    )
    check = VerificationCheck(
        name="candidate_health", outcome="pass", detail="ok", evidence_ids=("ev-0001",)
    )
    verification = VerificationResult(
        candidate_id=candidate_id,
        status="VERIFIED",
        reasons=(),
        checks=(check,),
        evidence_ids=("ev-0001",),
        candidate_snapshot="manual-candidate-c-01",
    )
    return candidate, application, verification


def _asked_decision(triplet, answer, **kwargs):
    candidate, application, verification = triplet
    return _decisions([candidate], [application], [verification], ask=lambda _: answer, **kwargs)


def test_all_decisions_default_to_pending():
    triplet = _verified_triplet()
    assert _asked_decision(triplet, "q") == {"c-01": "PENDING"}
    candidate, application, verification = triplet
    rejected = verification.model_copy(update={"status": "REJECTED"})
    params = {"json_mode": False, "tty": True}
    assert cli._collect_decisions([candidate], [application], [rejected], **params) == {
        "c-01": "PENDING"
    }


def test_verified_candidate_approve_reject_skip():
    triplet = _verified_triplet()
    assert _asked_decision(triplet, "a") == {"c-01": "APPROVED"}
    assert _asked_decision(triplet, "r") == {"c-01": "REJECTED"}
    assert _asked_decision(triplet, "s") == {"c-01": "PENDING"}
    assert _asked_decision(triplet, "bogus") == {"c-01": "PENDING"}
    assert _asked_decision(triplet, "") == {"c-01": "PENDING"}


def test_non_verified_candidates_are_never_prompted():
    candidate, application, verification = _verified_triplet()
    asked: list[str] = []

    def _ask(message):
        asked.append(message)
        return "a"

    for status in ("REJECTED", "UNVERIFIABLE"):
        bad = verification.model_copy(update={"status": status})
        assert _decisions([candidate], [application], [bad], ask=_ask) == {"c-01": "PENDING"}
    assert asked == []


def test_prompts_disabled_without_tty_or_in_json_mode():
    candidate, application, verification = _verified_triplet()
    asked: list[str] = []

    def _ask(message):
        asked.append(message)
        return "a"

    pending = {"c-01": "PENDING"}
    args = ([candidate], [application], [verification])
    assert _decisions(*args, tty=False, ask=_ask) == pending
    assert _decisions(*args, json_mode=True, ask=_ask) == pending
    assert asked == []


def test_decisions_require_no_network_or_filesystem_writes():
    candidate, application, verification = _verified_triplet()
    result = _decisions([candidate], [application], [verification], ask=lambda _: "a")
    assert result == {"c-01": "APPROVED"}


def test_json_stdout_is_pure_and_warnings_go_to_stderr(monkeypatch, tmp_path, capsys):
    tag = "manual"
    snap = _cand_name(tag, "c-01")
    answers = dict(_stage_a_answers(tag))
    answers[("traceroute", snap)] = [trace_row("ACCEPTED")]
    answers[("differentialReachability", snap)] = [differential_row("ACCEPTED", "ACCEPTED")]
    fake = StageCFake(answers=answers, delete_fail={snap})
    code = _run(monkeypatch, tmp_path, fake, [_route_candidate()], json=True)
    assert code == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["verifications"][0]["status"] == "VERIFIED"
    assert captured.err.strip() != ""
    assert "Candidate" not in captured.out


def test_stage_c_appears_in_human_readable_output(monkeypatch, tmp_path, capsys):
    tag = "manual"
    snap = _cand_name(tag, "c-01")
    answers = dict(_stage_a_answers(tag))
    answers[("traceroute", snap)] = [trace_row("ACCEPTED")]
    answers[("differentialReachability", snap)] = [differential_row("ACCEPTED", "ACCEPTED")]
    code = _run(monkeypatch, tmp_path, StageCFake(answers=answers), [_route_candidate()])
    assert code == 0
    out = capsys.readouterr().out
    assert "c-01" in out
    assert "VERIFIED" in out
    assert "ip route 198.51.100.0 255.255.255.0 10.0.12.2" in out
    assert "human decision" in out.lower()


def test_report_contains_no_absolute_paths_or_secrets(monkeypatch, tmp_path, capsys):
    tag = "manual"
    snap = _cand_name(tag, "c-01")
    answers = dict(_stage_a_answers(tag))
    answers[("traceroute", snap)] = [trace_row("ACCEPTED")]
    answers[("differentialReachability", snap)] = [differential_row("ACCEPTED", "ACCEPTED")]
    code = _run(monkeypatch, tmp_path, StageCFake(answers=answers), [_route_candidate()], json=True)
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    dumped = json.dumps(payload)
    assert str(tmp_path) not in dumped
    assert str(Path.home()) not in dumped.replace(str(tmp_path), "")
    for verification in payload["verifications"]:
        assert verification["candidate_snapshot"] == snap
        assert "/" not in verification["candidate_snapshot"]
    for application in payload["applications"]:
        assert application["changed_files"] == ["configs/r1.cfg"]


def test_candidate_dirs_removed_by_default(monkeypatch, tmp_path, capsys):
    tag = "manual"
    snap = _cand_name(tag, "c-01")
    answers = dict(_stage_a_answers(tag))
    answers[("traceroute", snap)] = [trace_row("ACCEPTED")]
    answers[("differentialReachability", snap)] = [differential_row("ACCEPTED", "ACCEPTED")]
    monkeypatch.delenv("KEEP_CANDIDATE_DIRS", raising=False)
    code = _run(monkeypatch, tmp_path, StageCFake(answers=answers), [_route_candidate()], json=True)
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["verifications"][0]["status"] == "VERIFIED"
    assert list((tmp_path / "runs").rglob("candidate-*")) == []


def test_candidate_dirs_retained_when_flag_enabled(monkeypatch, tmp_path, capsys):
    tag = "manual"
    snap = _cand_name(tag, "c-01")
    answers = dict(_stage_a_answers(tag))
    answers[("traceroute", snap)] = [trace_row("ACCEPTED")]
    answers[("differentialReachability", snap)] = [differential_row("ACCEPTED", "ACCEPTED")]
    monkeypatch.setenv("KEEP_CANDIDATE_DIRS", "true")
    code = _run(monkeypatch, tmp_path, StageCFake(answers=answers), [_route_candidate()], json=True)
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["verifications"][0]["status"] == "VERIFIED"
    kept = [p for p in (tmp_path / "runs").rglob("candidate-*") if p.is_dir()]
    assert len(kept) == 1
    assert "META_API_KEY" not in json.dumps(payload)


def test_run_network_cleanup_runs_after_candidate_cleanup(monkeypatch, tmp_path, capsys):
    tag = "manual"
    snap = _cand_name(tag, "c-01")
    answers = dict(_stage_a_answers(tag))
    answers[("traceroute", snap)] = [trace_row("ACCEPTED")]
    answers[("differentialReachability", snap)] = [differential_row("ACCEPTED", "ACCEPTED")]
    fake = StageCFake(answers=answers)
    code = _run(monkeypatch, tmp_path, fake, [_route_candidate()], json=True)
    assert code == 0
    assert fake.networks_deleted == ["run-net-abc123"]
    assert fake.events[-1] == ("network", "run-net-abc123")
    assert ("snapshot", snap) in fake.events


def test_baseline_and_proposed_snapshots_are_never_deleted(monkeypatch, tmp_path, capsys):
    tag = "manual"
    snap = _cand_name(tag, "c-01")
    answers = dict(_stage_a_answers(tag))
    answers[("traceroute", snap)] = [trace_row("ACCEPTED")]
    answers[("differentialReachability", snap)] = [differential_row("ACCEPTED", "ACCEPTED")]
    fake = StageCFake(answers=answers)
    code = _run(monkeypatch, tmp_path, fake, [_route_candidate()], json=True)
    assert code == 0
    assert "manual-baseline" not in fake.deleted
    assert "manual-proposed" not in fake.deleted
    for call in fake.init_calls:
        if call["name"] == snap:
            assert call["overwrite"] is False
    assert fake.networks_deleted == ["run-net-abc123"]


def _verified_answers(tag, candidate_id="c-01"):
    snap = _cand_name(tag, candidate_id)
    answers = dict(_stage_a_answers(tag))
    answers[("traceroute", snap)] = [trace_row("ACCEPTED")]
    answers[("differentialReachability", snap)] = [differential_row("ACCEPTED", "ACCEPTED")]
    return answers


def test_eof_during_approval_still_emits_report(monkeypatch, tmp_path, capsys):
    fake = StageCFake(answers=_verified_answers("manual"))
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)

    def _boom(*args, **kwargs):
        raise EOFError

    monkeypatch.setattr("builtins.input", _boom)
    code = _run(monkeypatch, tmp_path, fake, [_route_candidate()])
    assert code == 0
    captured = capsys.readouterr()
    assert "VERIFIED" in captured.out
    assert "PENDING" in captured.out
    assert "interrupted" in captured.err
    assert "Candidate c-01 is VERIFIED" not in captured.out


def test_keyboard_interrupt_during_approval_still_emits_report(monkeypatch, tmp_path, capsys):
    fake = StageCFake(answers=_verified_answers("manual"))
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    calls: list[str] = []

    def _interrupt(*args, **kwargs):
        calls.append("prompt")
        raise KeyboardInterrupt

    monkeypatch.setattr("builtins.input", _interrupt)
    code = _run(monkeypatch, tmp_path, fake, [_route_candidate()])
    assert code == 0
    captured = capsys.readouterr()
    assert "VERIFIED" in captured.out
    assert "PENDING" in captured.out
    assert "interrupted" in captured.err
    assert len(calls) == 1


def test_earlier_approval_survives_later_eof(monkeypatch, tmp_path, capsys):
    answers = _verified_answers("manual", "c-01")
    answers.update(_verified_answers("manual", "c-02"))
    fake = StageCFake(answers=answers)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    calls: list[str] = []

    def _approve_then_boom(*args, **kwargs):
        calls.append("prompt")
        if len(calls) == 1:
            return "a"
        raise EOFError

    monkeypatch.setattr("builtins.input", _approve_then_boom)
    code = _run(
        monkeypatch, tmp_path, fake, [_route_candidate("c-01"), _route_candidate("c-02")]
    )
    assert code == 0
    captured = capsys.readouterr()
    assert len(calls) == 2
    assert "APPROVED" in captured.out
    assert "PENDING" in captured.out
    assert "interrupted" in captured.err


def test_interactive_prompts_use_stderr_not_stdout(monkeypatch, tmp_path, capsys):
    fake = StageCFake(answers=_verified_answers("manual"))
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda *args, **kwargs: "a")
    code = _run(monkeypatch, tmp_path, fake, [_route_candidate()])
    assert code == 0
    captured = capsys.readouterr()
    assert "Candidate c-01 is VERIFIED" not in captured.out
    assert "[a]pprove" not in captured.out
    assert "Candidate c-01 is VERIFIED" in captured.err
    assert "[a]pprove" in captured.err
    assert "APPROVED" in captured.out


def test_ask_callable_keeps_single_string_argument():
    candidate, application, verification = _verified_triplet()
    seen: list[object] = []
    result = _decisions(
        [candidate], [application], [verification], ask=lambda message: seen.append(message) or "r"
    )
    assert result == {"c-01": "REJECTED"}
    assert len(seen) == 1
    assert isinstance(seen[0], str)


def test_json_mode_with_tty_disables_prompts(monkeypatch, tmp_path, capsys):
    fake = StageCFake(answers=_verified_answers("manual"))
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    calls: list[str] = []
    monkeypatch.setattr("builtins.input", lambda *args, **kwargs: calls.append("p") or "a")
    code = _run(monkeypatch, tmp_path, fake, [_route_candidate()], json=True)
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["human_decision"] == {"c-01": "PENDING"}
    assert calls == []


def test_init_failure_cleans_candidate_dir_and_run_root(monkeypatch, tmp_path, capsys):
    answers = _verified_answers("manual", "c-02")
    first = _cand_name("manual", "c-01")
    fake = StageCFake(answers=answers, init_fail={first})
    code = _run(
        monkeypatch, tmp_path, fake, [_route_candidate("c-01"), _route_candidate("c-02")],
        json=True,
    )
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    by_id = {v["candidate_id"]: v for v in payload["verifications"]}
    assert by_id["c-01"]["status"] == "UNVERIFIABLE"
    assert by_id["c-01"]["candidate_snapshot"] is None
    assert by_id["c-02"]["status"] == "VERIFIED"
    assert [a["applied"] for a in payload["applications"]] == [True, True]
    runs_root = tmp_path / "runs"
    leftovers = list(runs_root.rglob("candidate-*")) if runs_root.exists() else []
    assert leftovers == []
    assert not runs_root.exists() or list(runs_root.iterdir()) == []
    assert "manual-baseline" not in fake.deleted
    assert "manual-proposed" not in fake.deleted


def test_name_generation_failure_cleans_candidate_dir(monkeypatch, tmp_path, capsys):
    fake = StageCFake(answers=_verified_answers("manual"))

    def _bad_name(tag, candidate_id):
        raise BatfishError("bad tag")

    monkeypatch.setattr(pipeline, "candidate_snapshot_name", _bad_name)
    code = _run(monkeypatch, tmp_path, fake, [_route_candidate()], json=True)
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["verifications"][0]["status"] == "UNVERIFIABLE"
    assert payload["verifications"][0]["candidate_snapshot"] is None
    runs_root = tmp_path / "runs"
    leftovers = list(runs_root.rglob("candidate-*")) if runs_root.exists() else []
    assert leftovers == []


def test_protected_name_collision_cleans_candidate_dir(monkeypatch, tmp_path, capsys):
    fake = StageCFake(answers=_verified_answers("manual"))
    monkeypatch.setattr(
        pipeline, "candidate_snapshot_name", lambda tag, cid: f"{tag}-baseline"
    )
    code = _run(monkeypatch, tmp_path, fake, [_route_candidate()], json=True)
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["verifications"][0]["status"] == "UNVERIFIABLE"
    assert "manual-baseline" not in fake.deleted
    runs_root = tmp_path / "runs"
    leftovers = list(runs_root.rglob("candidate-*")) if runs_root.exists() else []
    assert leftovers == []


def test_already_registered_name_cleans_candidate_dir(monkeypatch, tmp_path, capsys):
    fake = StageCFake(answers=_verified_answers("manual"))
    fake._registered.add(_cand_name("manual", "c-01"))
    code = _run(monkeypatch, tmp_path, fake, [_route_candidate()], json=True)
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["verifications"][0]["status"] == "UNVERIFIABLE"
    runs_root = tmp_path / "runs"
    leftovers = list(runs_root.rglob("candidate-*")) if runs_root.exists() else []
    assert leftovers == []


def test_registration_failure_never_deletes_snapshot_but_cleans_dir(
    monkeypatch, tmp_path, capsys
):
    fake = StageCFake(answers=_verified_answers("manual"))
    snap = _cand_name("manual", "c-01")

    def _bad_register(name):
        raise BatfishError("registry unavailable")

    monkeypatch.setattr(fake, "register_candidate_snapshot", _bad_register)
    code = _run(monkeypatch, tmp_path, fake, [_route_candidate()], json=True)
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["verifications"][0]["status"] == "UNVERIFIABLE"
    assert snap not in fake.deleted
    assert "registration failed" in "; ".join(payload["verifications"][0]["reasons"])
    runs_root = tmp_path / "runs"
    leftovers = list(runs_root.rglob("candidate-*")) if runs_root.exists() else []
    assert leftovers == []
    assert fake.networks_deleted == ["run-net-abc123"]


def test_retention_keeps_run_root_and_candidate_dir(monkeypatch, tmp_path, capsys):
    fake = StageCFake(answers=_verified_answers("manual"))
    monkeypatch.setenv("KEEP_CANDIDATE_DIRS", "true")
    code = _run(monkeypatch, tmp_path, fake, [_route_candidate()], json=True)
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["verifications"][0]["status"] == "VERIFIED"
    runs_root = tmp_path / "runs"
    assert runs_root.is_dir()
    kept = [p for p in runs_root.rglob("candidate-*") if p.is_dir()]
    assert len(kept) == 1


def test_directory_cleanup_failure_warns_without_masking(monkeypatch, tmp_path, capsys):
    fake = StageCFake(answers=_verified_answers("manual"))

    def _boom(target):
        raise OSError("disk read-only")

    monkeypatch.setattr(pipeline.shutil, "rmtree", _boom)
    code = _run(monkeypatch, tmp_path, fake, [_route_candidate()], json=True)
    assert code == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["verifications"][0]["status"] == "VERIFIED"
    assert "cleanup failed" in captured.err


def test_unrelated_directories_are_never_removed(monkeypatch, tmp_path, capsys):
    keeper = tmp_path / "runs" / "keep-me"
    keeper.mkdir(parents=True)
    (keeper / "notes.txt").write_text("do not delete")
    warnings: list[str] = []
    pipeline._remove_candidate_dir(
        tmp_path / "runs", tmp_path / "runs" / "root", warnings.append
    )
    pipeline._remove_candidate_dir(keeper, tmp_path / "other-root", warnings.append)
    assert (keeper / "notes.txt").read_text() == "do not delete"
    assert (tmp_path / "runs").is_dir()
    assert warnings != []


def test_fail_plus_unknown_is_unverifiable_end_to_end(monkeypatch, tmp_path, capsys):
    from tests._fakes import multi_differential_row

    tag = "manual"
    snap = _cand_name(tag, "c-01")
    truncated_b = multi_differential_row(
        ["ACCEPTED"], ["DENIED_IN"], snapshot_total=6, reference_total=1, flow=_TCP22
    )
    answers = {
        ("traceroute", "manual-baseline"): [
            trace_row("NO_ROUTE"),
            trace_row("DENIED_IN", flow=_TCP22),
            trace_row("ACCEPTED", flow=_TCP1433),
        ],
        ("traceroute", "manual-proposed"): [
            trace_row("NO_ROUTE"),
            trace_row("DENIED_IN", flow=_TCP22),
            trace_row("NO_ROUTE", flow=_TCP1433),
        ],
        ("differentialReachability", "manual-proposed"): [
            differential_row("NO_ROUTE", "NO_ROUTE"),
            differential_row("DENIED_IN", "DENIED_IN", flow=_TCP22),
            differential_row("NO_ROUTE", "ACCEPTED", flow=_TCP1433),
        ],
        ("traceroute", snap): [
            trace_row("ACCEPTED"),
            trace_row("ACCEPTED", flow=_TCP22),
            trace_row("ACCEPTED", flow=_TCP1433),
        ],
        ("differentialReachability", snap): [
            differential_row("ACCEPTED", "NO_ROUTE"),
            truncated_b,
            differential_row("ACCEPTED", "ACCEPTED", flow=_TCP1433),
        ],
    }
    _pair_run(monkeypatch, tmp_path, answers, json=True)
    ver = json.loads(capsys.readouterr().out)["verifications"][0]
    assert ver["status"] == "UNVERIFIABLE"
    by_name = {c["name"]: c["outcome"] for c in ver["checks"]}
    assert by_name["intent:flow-b"] == "fail"
    assert by_name["no_regression:flow-b"] == "unknown"
