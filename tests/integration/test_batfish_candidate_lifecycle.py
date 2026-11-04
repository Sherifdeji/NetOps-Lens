"""Controlled live-Batfish candidate lifecycle (opt-in, no model calls).

Exercises the REAL production path against the already-running Batfish
service: disposable run-scoped network, real snapshot init, real Stage A,
deterministic scripted Stage B (a canned transport driving the genuine
``run_stage_b`` validation — never Muse/Meta API), real Phase 4.1
application, real Batfish candidate snapshot + registration, real
Phase 4.2 verification, guarded deletion, and run-network cleanup.

Safety:

- The working network is always a fresh ``run_network_name(...)`` UUID
  value, never ``netops-lens-lab``.
- Only the current run's candidate snapshot and network are ever deleted.
- Post-run probes never call ``connect()`` on the disposable name:
  pybatfish ``set_network`` auto-creates a missing network, so that would
  resurrect what cleanup just removed. Deletion is proven by a second
  ``delete_network()`` raising ``BatfishError`` instead.
- Offline snapshot analysis only: no live devices, no deployment.

Run explicitly (never part of ``pytest -q``)::

    NETOPS_LENS_RUN_BATFISH_INTEGRATION=1 \\
        python -m pytest -m integration tests/integration -q
"""

from __future__ import annotations

import json

import pytest

from netops_lens import cli
from netops_lens.agent import run_stage_b as real_run_stage_b
from netops_lens.batfish_client import (
    BatfishClient,
    BatfishError,
    candidate_snapshot_name,
)
from netops_lens.cli import run_network_name
from netops_lens.config import load_settings
from netops_lens.evidence import EvidenceStore
from netops_lens.models import SnapshotRef
from netops_lens.tools import get_snapshot_health

pytestmark = pytest.mark.integration

SHARED_NETWORK = "netops-lens-lab"
FLOW_ID = "app-to-db-icmp"
SUBMIT_ARGS = {
    "rationale": "restore the missing static route evidenced on baseline",
    "operations": [
        {
            "op": "add_static_route",
            "node": "r1",
            "prefix": "198.51.100.0/24",
            "next_hop": "10.0.12.2",
        }
    ],
    "target_flow_ids": [FLOW_ID],
}


class ScriptedTransport:
    """Deterministic stand-in for the model: get_routes, submit, done."""

    def __init__(self) -> None:
        self.calls = 0
        self.script = [
            {
                "content": None,
                "tool_calls": [
                    {
                        "id": "call-1",
                        "name": "get_routes",
                        "arguments": json.dumps({"snapshot": "baseline", "node": "r1"}),
                    }
                ],
            },
            {
                "content": None,
                "tool_calls": [
                    {
                        "id": "call-2",
                        "name": "submit_candidate_patch",
                        "arguments": json.dumps(SUBMIT_ARGS),
                    }
                ],
            },
            {
                "content": "Deterministic integration repair: missing route restored.",
                "tool_calls": [],
            },
        ]

    def __call__(self, messages: list, tools: list) -> dict:
        self.calls += 1
        if self.script:
            return self.script.pop(0)
        return {"content": "done", "tool_calls": []}


def _recording_client(events: list, seen: dict):
    """Thin recording subclass of the REAL BatfishClient (no reimplementation)."""
    real = cli.BatfishClient

    class RecordingClient(real):  # type: ignore[valid-type,misc]
        def connect(self) -> None:
            super().connect()
            seen["network"] = self.network

        def init_snapshot(self, path, name, *, overwrite=True):
            events.append(("init_snapshot", name, overwrite))
            return super().init_snapshot(path, name, overwrite=overwrite)

        def register_candidate_snapshot(self, name):
            events.append(("register", name))
            return super().register_candidate_snapshot(name)

        def delete_snapshot(self, name):
            events.append(("delete_snapshot", name))
            return super().delete_snapshot(name)

        def delete_network(self):
            events.append(("delete_network", self.network))
            return super().delete_network()

    return RecordingClient


def _hermetic_settings(monkeypatch) -> object:
    """Drop env overrides that would reroute this run's lifecycle."""
    for var in (
        "KEEP_CANDIDATE_DIRS",
        "CANDIDATE_SUBMISSION_VARIANT",
        "MAX_CANDIDATES",
        "MAX_PATCH_RETRIES",
        "AGENT_MAX_TOOL_CALLS",
    ):
        monkeypatch.delenv(var, raising=False)
    return load_settings()


def _scripted_stage_b(client, store, assessment, intent, baseline, proposed, **kwargs):
    """The real Stage B with a canned transport: no model, full validation."""
    return real_run_stage_b(
        client,
        store,
        assessment,
        intent,
        baseline,
        proposed,
        question=kwargs.get("question", ""),
        transport=ScriptedTransport(),
    )


def _read_only_network_names(host: str) -> list[str]:
    """List Batfish networks without selecting or creating any of them.

    I-01: the production ``connect()`` path calls ``set_network()``,
    which auto-creates a missing network — so a presence probe must
    never go through it. ``Session.list_networks()`` is a read-only GET
    returning ``list[str]``.
    """
    from pybatfish.client.session import Session

    return [str(name) for name in Session(host=host).list_networks()]


def _require_shared_network(host: str, name: str) -> None:
    """Skip unless the shared network is already listed. Never creates it."""
    try:
        names = _read_only_network_names(host)
    except Exception as exc:
        pytest.skip(
            f"Batfish unreachable at {host}: {type(exc).__name__}; "
            "integration test skipped"
        )
    if name not in names:
        pytest.skip(
            f"prerequisite shared network {name!r} is absent; refusing to create it"
        )


def test_shared_probe_uses_read_only_listing(monkeypatch):
    """I-01: the probe lists networks; it never selects or creates one.

    Contacts nothing live: the pybatfish Session is faked, so this proves
    the implementation path without reaching any Batfish service.
    """
    calls: list = []

    class FakeSession:
        def __init__(self, host=None):
            calls.append(("init", host))

        def list_networks(self):
            calls.append(("list_networks",))
            return ["netops-lens-lab", "other"]

        def set_network(self, name):  # pragma: no cover - must never run
            calls.append(("set_network", name))
            raise AssertionError("presence probe must not select a network")

    monkeypatch.setattr("pybatfish.client.session.Session", FakeSession)
    assert _read_only_network_names("some-host") == ["netops-lens-lab", "other"]
    assert ("list_networks",) in calls
    assert not [c for c in calls if c[0] in ("set_network", "init_snapshot", "delete_network")]


def test_smoke_connect_init_health_and_cleanup(monkeypatch):
    """Real Batfish: disposable network, snapshot init, health, cleanup."""
    settings = _hermetic_settings(monkeypatch)
    host = settings.batfish_host
    network = run_network_name(settings.batfish_network, "integration-smoke")
    assert network != settings.batfish_network
    assert network != SHARED_NETWORK
    assert network.startswith(settings.batfish_network + "-")
    assert run_network_name(settings.batfish_network, "t") != run_network_name(
        settings.batfish_network, "t"
    )

    from netops_lens.cli import REPO_ROOT

    print(f"[integration] disposable network: {network}")
    tag = "smoke"
    client = BatfishClient(host, network)
    try:
        client.connect()
        assert client.network == network
        client.init_snapshot(REPO_ROOT / "lab" / "baseline", f"{tag}-baseline")
        client.init_snapshot(REPO_ROOT / "lab" / "proposed", f"{tag}-proposed")
        store = EvidenceStore()
        base_health = get_snapshot_health(
            client, store, SnapshotRef(name=f"{tag}-baseline", path="lab/baseline")
        )[1]
        prop_health = get_snapshot_health(
            client, store, SnapshotRef(name=f"{tag}-proposed", path="lab/proposed")
        )[1]
        assert base_health.status == "OK", base_health.reasons
        assert prop_health.status == "OK", prop_health.reasons
    finally:
        try:
            client.delete_network()
        except BatfishError as exc:
            pytest.fail(f"smoke cleanup failed; disposable network left behind: {network} ({exc})")
    # Deletion proof without resurrecting: deleting again must raise.
    with pytest.raises(BatfishError):
        BatfishClient(host, network).delete_network()


def test_route_repair_lifecycle_end_to_end(monkeypatch, tmp_path, capsys):
    """Full production run_assess path with deterministic Stage B injection."""
    settings = _hermetic_settings(monkeypatch)
    _require_shared_network(settings.batfish_host, SHARED_NETWORK)

    events: list = []
    seen: dict = {}
    monkeypatch.setattr(cli, "BatfishClient", _recording_client(events, seen))
    monkeypatch.setattr(cli, "run_stage_b", _scripted_stage_b)

    args = cli.build_parser().parse_args(
        ["assess", "--scenario", "removed_route", "--json"]
    )
    code = cli.run_assess(args)
    assert code == 0, capsys.readouterr().err

    payload = json.loads(capsys.readouterr().out)
    network = seen["network"]
    print(f"[integration] disposable network: {network}")
    assert network != settings.batfish_network
    assert network != SHARED_NETWORK
    assert network.startswith(settings.batfish_network + "-removed-route-")

    # Stage A detected the route regression on real Batfish evidence.
    assert payload["assessment"]["verdict"] == "REGRESSION_DETECTED"

    # Deterministic Stage B submitted exactly one validated route candidate.
    investigation = payload["investigation"]
    assert len(investigation["candidates"]) == 1
    candidate = investigation["candidates"][0]
    assert candidate["candidate_id"] == "c-01"
    assert candidate["operations"][0]["op"] == "add_static_route"

    # Phase 4.1 applied it; Phase 4.2 verified it against real Batfish.
    cand_snap = candidate_snapshot_name("removed_route", "c-01")
    assert payload["applications"][0]["applied"] is True
    verification = payload["verifications"][0]
    assert verification["status"] == "VERIFIED"
    assert verification["candidate_snapshot"] == cand_snap
    assert payload["human_decision"] == {"c-01": "PENDING"}

    # Production lifecycle order, with production argument values.
    inits = [e for e in events if e[0] == "init_snapshot"]
    assert ("init_snapshot", "removed_route-baseline", True) in inits
    assert ("init_snapshot", "removed_route-proposed", True) in inits
    cand_inits = [e for e in inits if "candidate" in e[1]]
    assert cand_inits == [("init_snapshot", cand_snap, False)]
    # I-02: relative lifecycle order on this run's own candidate/network.
    init_idx = events.index(("init_snapshot", cand_snap, False))
    reg_idx = events.index(("register", cand_snap))
    del_idx = events.index(("delete_snapshot", cand_snap))
    net_idx = events.index(("delete_network", network))
    assert init_idx < reg_idx < del_idx < net_idx
    assert events[-1] == ("delete_network", network)
    assert [e for e in events if e[0] == "delete_network"] == [("delete_network", network)]
    assert "removed_route-baseline" not in [e[1] for e in events if e[0] == "delete_snapshot"]
    assert "removed_route-proposed" not in [e[1] for e in events if e[0] == "delete_snapshot"]

    # No candidate working directories leak into the repo.
    runs_root = cli.REPO_ROOT / "runs"
    leftovers = list(runs_root.rglob("candidate-*")) if runs_root.exists() else []
    assert leftovers == []

    # Server-side cleanup proof: the disposable network is really gone.
    with pytest.raises(BatfishError):
        BatfishClient(settings.batfish_host, network).delete_network()

    # Shared network untouched: still listed (read-only check, never connect).
    assert SHARED_NETWORK in _read_only_network_names(settings.batfish_host)
    # Our run never targeted it for deletion in the first place.
    assert all(e[1] != SHARED_NETWORK for e in events if e[0] == "delete_network")
