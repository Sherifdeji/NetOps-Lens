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
