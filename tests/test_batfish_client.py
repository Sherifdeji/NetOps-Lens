"""Unit tests for batfish_client conversion and error paths (no Docker).

Live-Batfish behavior is covered by tests/test_phase1_integration.py; this
module pins the DataFrame boundary with synthetic frames only.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pandas as pd
import pytest

from netops_lens.batfish_client import (
    BatfishClient,
    BatfishError,
    HealthRecords,
    candidate_snapshot_name,
    to_records,
)


class _FakeModel:
    """Stand-in for a Pybatfish datamodel object exposing .dict()."""

    def __init__(self, payload):
        self._payload = payload

    def dict(self):
        return self._payload


def test_to_records_converts_cells_and_stays_json_serializable():
    frame = pd.DataFrame(
        [
            {
                "File_Name": "configs/r1.cfg",
                "Status": "PASSED",
                "Nodes": ["r1"],
                "Missing": float("nan"),
                "Count": __import__("numpy").int64(2),
            },
            {
                "File_Name": "configs/r2.cfg",
                "Status": "PASSED",
                "Nodes": ["r2"],
                "Missing": None,
                "Count": 1,
            },
        ]
    )
    records = to_records(frame, question="fileParseStatus")
    assert records[0]["Missing"] is None
    assert records[0]["Count"] == 2
    assert records[1]["Nodes"] == ["r2"]
    json.dumps(records)


def test_to_records_expands_datamodel_objects():
    frame = pd.DataFrame(
        [
            {
                "Flow": _FakeModel({"srcIp": "192.0.2.10"}),
                "Traces": [_FakeModel({"disposition": "ACCEPTED", "hops": []})],
            }
        ]
    )
    records = to_records(frame, question="traceroute")
    assert records[0]["Flow"] == {"srcIp": "192.0.2.10"}
    assert records[0]["Traces"][0]["disposition"] == "ACCEPTED"
    json.dumps(records)


def test_to_records_rejects_unconvertible_cells():
    frame = pd.DataFrame([{"Flow": object()}])
    with pytest.raises(BatfishError):
        to_records(frame, question="traceroute")


def test_client_requires_connect_and_known_questions():
    client = BatfishClient(host="localhost", network="netops-lens-lab")
    with pytest.raises(BatfishError, match="not connected"):
        client.init_snapshot("lab/baseline", name="x")
    client._session = SimpleNamespace(q=SimpleNamespace(), init_snapshot=lambda *a, **k: None)
    with pytest.raises(BatfishError, match="unknown Batfish question"):
        client.ask("noSuchQuestion", "baseline")


def test_init_snapshot_rejects_missing_directory():
    client = BatfishClient(host="localhost", network="netops-lens-lab")
    client._session = SimpleNamespace(q=SimpleNamespace(), init_snapshot=lambda *a, **k: None)
    with pytest.raises(BatfishError, match="snapshot directory not found"):
        client.init_snapshot("lab/does-not-exist", name="x")


def test_health_records_shape():
    records = HealthRecords(
        parse_status=({"Status": "PASSED"},),
        init_issues=(),
        nodes=({"Node": "r1"}, {"Node": "r2"}),
    )
    assert records.init_issues == ()
    assert [n["Node"] for n in records.nodes] == ["r1", "r2"]


class _RecordingSession:
    """Fake Pybatfish session recording deletions and failing on demand."""

    def __init__(self, calls, error=None):
        self._calls = calls
        self._error = error

    def delete_snapshot(self, name):
        self._calls.append(name)
        if self._error is not None:
            raise self._error


def _missing_snapshot_error():
    response = SimpleNamespace(status_code=404)
    error = Exception("404 Client Error: Not Found")
    error.response = response  # type: ignore[attr-defined]
    return error


def test_delete_snapshot_refuses_unregistered_without_session_call(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "netops_lens.batfish_client.Session",
        lambda *args, **kwargs: _RecordingSession(calls),
    )
    client = BatfishClient(host="localhost", network="net")
    with pytest.raises(BatfishError, match="non-candidate"):
        client.delete_snapshot("baseline")
    with pytest.raises(BatfishError, match="non-candidate"):
        client.delete_snapshot("proposed")
    # Well-formed but never registered: refused without any Session call.
    with pytest.raises(BatfishError, match="unregistered"):
        client.delete_snapshot("run9-candidate-c-99")
    assert calls == []


def test_register_candidate_snapshot_rejects_non_generated_names():
    client = BatfishClient(host="localhost", network="net")
    for bad in (
        "baseline",
        "proposed",
        "run1-proposed",
        "healthy-baseline",
        "netops-lens-lab",
        "../evil",
        "run1-candidate-c-01/..",
        "RUN1-candidate-c-01",
    ):
        with pytest.raises(BatfishError, match="non-candidate"):
            client.register_candidate_snapshot(bad)
    assert client._candidate_snapshots == set()


def test_register_candidate_snapshot_accepts_generated_names(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "netops_lens.batfish_client.Session",
        lambda *args, **kwargs: _RecordingSession(calls),
    )
    client = BatfishClient(host="localhost", network="net")
    name = candidate_snapshot_name("nightly", "c-07")
    client.register_candidate_snapshot(name)
    client.delete_snapshot(name)
    assert calls == [name]


def test_delete_snapshot_registered_name_deletes_and_unregisters():
    calls = []
    client = BatfishClient(host="localhost", network="net")
    client._session = _RecordingSession(calls)
    client.register_candidate_snapshot("run1-candidate-c-01")
    client.delete_snapshot("run1-candidate-c-01")
    assert calls == ["run1-candidate-c-01"]
    with pytest.raises(BatfishError, match="unregistered"):
        client.delete_snapshot("run1-candidate-c-01")
    assert calls == ["run1-candidate-c-01"]


def test_delete_snapshot_missing_unregisters_but_surfaces_batfish_error():
    calls = []
    client = BatfishClient(host="localhost", network="net")
    client._session = _RecordingSession(calls, error=_missing_snapshot_error())
    client.register_candidate_snapshot("run1-candidate-c-01")
    with pytest.raises(BatfishError, match="already absent"):
        client.delete_snapshot("run1-candidate-c-01")
    assert calls == ["run1-candidate-c-01"]
    with pytest.raises(BatfishError, match="unregistered"):
        client.delete_snapshot("run1-candidate-c-01")


def test_delete_snapshot_other_errors_keep_registration():
    calls = []
    client = BatfishClient(host="localhost", network="net")
    client._session = _RecordingSession(calls, error=RuntimeError("boom"))
    client.register_candidate_snapshot("run1-candidate-c-01")
    with pytest.raises(BatfishError, match="cannot delete snapshot"):
        client.delete_snapshot("run1-candidate-c-01")
    client._session = _RecordingSession(calls)
    client.delete_snapshot("run1-candidate-c-01")
    assert calls == ["run1-candidate-c-01", "run1-candidate-c-01"]


def test_delete_snapshot_uses_transient_session_when_unconnected(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "netops_lens.batfish_client.Session",
        lambda *args, **kwargs: _RecordingSession(calls),
    )
    client = BatfishClient(host="localhost", network="net")
    client.register_candidate_snapshot("run1-candidate-c-01")
    client.delete_snapshot("run1-candidate-c-01")
    assert calls == ["run1-candidate-c-01"]


def test_candidate_snapshot_name_sanitizes_tag_and_validates_id():
    assert candidate_snapshot_name("run1", "c-01") == "run1-candidate-c-01"
    assert candidate_snapshot_name("My Tag!", "c-12") == "my-tag--candidate-c-12"
    for bad_id in ("01", "c-1x", "baseline", "", "c-"):
        with pytest.raises(BatfishError, match="candidate id"):
            candidate_snapshot_name("run1", bad_id)
    with pytest.raises(BatfishError, match="snapshot tag"):
        candidate_snapshot_name("", "c-01")
    # Same convention as cli.run_network_name: symbols become dashes.
    assert candidate_snapshot_name("!!!", "c-01") == "----candidate-c-01"
