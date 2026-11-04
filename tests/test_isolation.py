"""F-08/N-03 snapshot-isolation tests. No live server mutation: all fakes."""

from __future__ import annotations

from types import SimpleNamespace

from netops_lens import cli, pipeline


def test_run_network_names_are_unique_and_safe():
    names = {cli.run_network_name("netops-lens-lab", "removed_route") for _ in range(50)}
    assert len(names) == 50
    for name in names:
        assert name.startswith("netops-lens-lab-removed-route-")
        assert all(c.isalnum() or c == "-" for c in name)


def test_run_network_name_uses_configured_prefix():
    name = cli.run_network_name("custom-net_01", "acl")
    assert name.startswith("custom-net-01-acl-")
    assert all(c.isalnum() or c == "-" for c in name)


def test_run_network_name_sanitizes_tag():
    name = cli.run_network_name("netops-lens-lab", "ACL Blocks/DB!")
    assert all(c.isalnum() or c == "-" for c in name)
    assert name.startswith("netops-lens-lab-acl-blocks-db--")


def test_run_network_name_never_equals_prefix():
    for tag in ("", "x", "lab"):
        name = cli.run_network_name("netops-lens-lab", tag)
        assert name != "netops-lens-lab"


def test_cleanup_run_network_reports_failure_without_raising():
    from netops_lens.batfish_client import BatfishError

    class FailingClient:
        network = "netops-lens-lab-manual-abcdef01"

        def delete_network(self):
            raise BatfishError("boom")

    assert cli.cleanup_run_network(FailingClient()) is False  # type: ignore[arg-type]


def test_cleanup_run_network_success():
    class OkClient:
        network = "netops-lens-lab-manual-abcdef01"

        def __init__(self):
            self.deleted = 0

        def delete_network(self):
            self.deleted += 1

    fake = OkClient()
    assert cli.cleanup_run_network(fake, protected="netops-lens-lab") is True  # type: ignore[arg-type]
    assert fake.deleted == 1


def test_cleanup_run_network_never_deletes_protected_network(capsys):
    """N-03: the shared configured network is refused, never deleted."""

    class SharedClient:
        network = "netops-lens-lab"

        def delete_network(self):  # pragma: no cover - must never run
            raise AssertionError("protected network must never be deleted")

    assert cli.cleanup_run_network(SharedClient(), protected="netops-lens-lab") is False  # type: ignore[arg-type]
    assert "refusing to delete protected network" in capsys.readouterr().err


def _parse(tmp_path):
    intent = tmp_path / "intent.yaml"
    intent.write_text("version: 1\nmust_reach: []\nmust_not_reach: []\n")
    return cli.build_parser().parse_args(
        [
            "assess",
            "--baseline",
            str(tmp_path),
            "--proposed",
            str(tmp_path),
            "--intent",
            str(intent),
        ]
    )


def test_run_assess_deletes_network_on_snapshot_error(monkeypatch, tmp_path, capsys):
    """Even the snapshot-error path must attempt network cleanup."""
    from netops_lens.batfish_client import BatfishError

    deleted: list[str] = []

    class FakeClient:
        def __init__(self, host, network):
            self.network = network

        def connect(self):
            return None

        def init_snapshot(self, path, name, **kwargs):
            raise BatfishError("no such dir")

        def delete_network(self):
            deleted.append(self.network)

    monkeypatch.setattr(cli, "BatfishClient", FakeClient)
    assert cli.run_assess(_parse(tmp_path)) == 1
    assert len(deleted) == 1
    assert deleted[0].startswith("netops-lens-lab-manual-")
    capsys.readouterr()


def test_run_assess_deletes_network_on_connect_error(monkeypatch, tmp_path, capsys):
    """N-03: a partially failed setup still cleans up its own network."""
    from netops_lens.batfish_client import BatfishError

    deleted: list[str] = []

    class FakeClient:
        def __init__(self, host, network):
            self.network = network

        def connect(self):
            raise BatfishError("set_network blew up halfway")

        def delete_network(self):
            deleted.append(self.network)

    monkeypatch.setattr(cli, "BatfishClient", FakeClient)
    assert cli.run_assess(_parse(tmp_path)) == 1
    assert len(deleted) == 1
    assert deleted[0].startswith("netops-lens-lab-manual-")
    assert "Batfish unavailable" in capsys.readouterr().err


def test_run_assess_deletes_network_on_success(monkeypatch, tmp_path, capsys):
    """The success path must also clean up its run-scoped network."""
    deleted: list[str] = []

    class FakeClient:
        def __init__(self, host, network):
            self.network = network

        def connect(self):
            return None

        def init_snapshot(self, path, name, **kwargs):
            return name

        def delete_network(self):
            deleted.append(self.network)

    def fake_assessment(*args, **kwargs):
        return SimpleNamespace(verdict="NO_REGRESSION_DETECTED")

    class FakeReport:
        applications: list = []
        investigation = None

        def __init__(self):
            self.assessment = SimpleNamespace(verdict="NO_REGRESSION_DETECTED")

        def model_dump_json(self, **kwargs):
            return '{"verdict": "NO_REGRESSION_DETECTED"}'

    monkeypatch.setattr(cli, "BatfishClient", FakeClient)
    monkeypatch.setattr(pipeline, "run_mandatory_assessment", fake_assessment)
    monkeypatch.setattr(pipeline, "assemble_report", lambda *a, **k: FakeReport())
    args = _parse(tmp_path)
    args.json = True
    assert cli.run_assess(args) == 0
    assert len(deleted) == 1
    assert deleted[0].startswith("netops-lens-lab-manual-")
    capsys.readouterr()


def test_run_assess_uses_configured_prefix(monkeypatch, tmp_path):
    """N-03: BATFISH_NETWORK configures the run-network prefix."""
    import os

    monkeypatch.setenv("BATFISH_NETWORK", "tenant-42")
    seen: list[str] = []

    class FakeClient:
        def __init__(self, host, network):
            self._network = network
            seen.append(network)

        @property
        def network(self):
            return self._network

        def connect(self):
            return None

        def init_snapshot(self, path, name, **kwargs):
            return name

        def delete_network(self):
            return None

    def fake_assessment(*args, **kwargs):
        return SimpleNamespace(verdict="NO_REGRESSION_DETECTED")

    class FakeReport:
        applications: list = []
        investigation = None

        def __init__(self):
            self.assessment = SimpleNamespace(verdict="NO_REGRESSION_DETECTED")

        def model_dump_json(self, **kwargs):
            return "{}"

    monkeypatch.setattr(cli, "BatfishClient", FakeClient)
    monkeypatch.setattr(pipeline, "run_mandatory_assessment", fake_assessment)
    monkeypatch.setattr(pipeline, "assemble_report", lambda *a, **k: FakeReport())
    args = _parse(tmp_path)
    args.json = True
    assert cli.run_assess(args) == 0
    assert len(seen) == 1
    assert seen[0].startswith("tenant-42-manual-")
    assert os.environ["BATFISH_NETWORK"] == "tenant-42"
