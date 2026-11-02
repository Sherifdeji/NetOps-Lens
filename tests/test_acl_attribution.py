"""F-09 ACL-attribution tests: no silent skips, explicit uncertainty records."""

from __future__ import annotations

from pathlib import Path

from netops_lens.models import FlowSpec
from netops_lens.tools import _identify_filter
from tests._fakes import FakeClient

REPO_ROOT = Path(__file__).resolve().parent.parent
PROPOSED_DIR = REPO_ROOT / "lab" / "scenarios" / "acl_blocks_db" / "proposed"
START = "@enter(r1[GigabitEthernet0/1])"

DENY_1433 = "10 deny tcp 192.0.2.0 0.0.0.255 198.51.100.0 0.0.0.255 eq 1433"


def _flow(**overrides) -> FlowSpec:
    payload = {
        "flow_id": "f-db",
        "src_ip": "192.0.2.10",
        "dst_ip": "198.51.100.10",
        "protocol": "TCP",
        "dst_port": 1433,
        "start_location": START,
    }
    payload.update(overrides)
    return FlowSpec(**payload)


def _call(client, rows=None, *, snapshot_path=PROPOSED_DIR, failures=None):
    answers = {("testFilters", "snap"): rows if rows is not None else []}
    fake = FakeClient(answers=answers, failures=failures or set())
    return _identify_filter(
        fake,
        _flow(),
        snapshot_name="snap",
        snapshot_path=str(snapshot_path),
        node="r1",
        filter_name="DB-FILTER",
    )


def test_exact_unique_match_against_proposed_config():
    out = _call(None, rows=[{"Action": "DENY", "Line_Content": DENY_1433}])
    assert out["resolution"] == "unique-match", out
    assert out["sequence_number"] == 10
    assert out["sequence_source"] == "config-parser"
    assert out["unparseable_rows"] == []
    assert out["reason"] is None


def test_unparseable_only_row_is_unresolved_not_silent():
    out = _call(None, rows=[{"Action": "DENY", "Line_Content": "bogus line without seq"}])
    assert out["resolution"] == "unresolved"
    assert len(out["unparseable_rows"]) == 1
    row = out["unparseable_rows"][0]
    assert row["matched_line_content"] == "bogus line without seq"
    assert row["parse_error"]
    assert out["candidates"] == []


def test_missing_line_content_recorded_explicitly():
    out = _call(None, rows=[{"Action": "DENY", "Line_Content": None}])
    assert out["resolution"] == "unresolved"
    assert out["unparseable_rows"][0]["parse_error"] == "missing or non-string Line_Content"


def test_valid_match_plus_unparseable_is_incomplete():
    out = _call(
        None,
        rows=[
            {"Action": "DENY", "Line_Content": DENY_1433},
            {"Action": "DENY", "Line_Content": "not a rule line"},
        ],
    )
    assert out["resolution"] == "incomplete", out
    assert len(out["candidates"]) == 1
    assert len(out["unparseable_rows"]) == 1
    assert "must not be used for patching" in out["reason"]


def test_duplicate_candidate_lines_are_ambiguous():
    out = _call(
        None,
        rows=[
            {"Action": "DENY", "Line_Content": DENY_1433},
            {"Action": "DENY", "Line_Content": DENY_1433},
        ],
    )
    assert out["resolution"] == "ambiguous", out
    assert len(out["candidates"]) == 2
    assert "refusing to guess" in out["reason"]


def test_parseable_but_unreconciled_line_is_unresolved():
    out = _call(None, rows=[{"Action": "DENY", "Line_Content": "10 deny tcp any any eq 9999"}])
    assert out["resolution"] == "unresolved", out
    assert out["candidates"][0]["sequence_number"] is None
    assert out["candidates"][0]["parser_error"] is None


def test_testfilters_failure_recorded_not_raised():
    out = _call(None, failures={("testFilters", "snap")})
    assert out["resolution"] == "testfilters-unavailable"
    assert "fake failure" in out["reason"]
    assert out["candidates"] == []


def test_empty_testfilters_result_is_unresolved():
    out = _call(None, rows=[])
    assert out["resolution"] == "unresolved"
    assert "no rule line reconciled" in out["reason"]


def test_filter_identity_preserved_on_every_record():
    out = _call(None, rows=[{"Action": "DENY", "Line_Content": "junk"}])
    assert out["node"] == "r1"
    assert out["filter"] == "DB-FILTER"


def test_config_load_failure_marks_parser_error(tmp_path):
    cfg_dir = tmp_path / "configs"
    cfg_dir.mkdir()
    (cfg_dir / "r1.cfg").write_text(
        "hostname r1\nip access-list extended DB-FILTER\n remark no rules parseable?\n!\n"
    )
    out = _call(
        None,
        rows=[{"Action": "DENY", "Line_Content": DENY_1433}],
        snapshot_path=tmp_path,
    )
    assert out["resolution"] == "unresolved", out
    assert out["candidates"][0]["parser_error"]
