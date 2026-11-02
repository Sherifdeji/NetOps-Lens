"""Intent loader tests (no Batfish, no LLM)."""

from __future__ import annotations

from pathlib import Path

import pytest

from netops_lens.intent import IntentError, load_intent

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_load_core_intent():
    intent = load_intent(REPO_ROOT / "examples" / "intent.yaml")
    assert intent.version == 1
    assert [f.flow_id for f in intent.must_reach] == ["app-to-db-icmp"]
    assert intent.must_not_reach == []
    flow = intent.must_reach[0]
    assert str(flow.src_ip) == "192.0.2.10"
    assert str(flow.dst_ip) == "198.51.100.1"
    assert flow.protocol.value == "ICMP"
    assert flow.dst_port is None


def test_load_acl_intent():
    intent = load_intent(REPO_ROOT / "examples" / "intent-acl.yaml")
    assert [f.flow_id for f in intent.must_reach] == ["app-to-db-authorized"]
    assert [f.flow_id for f in intent.must_not_reach] == ["app-to-db-unauthorized"]
    assert intent.must_reach[0].dst_port == 1433
    assert intent.must_not_reach[0].dst_port == 22


def test_missing_and_malformed_files(tmp_path):
    with pytest.raises(IntentError, match="not found"):
        load_intent(tmp_path / "absent.yaml")
    bad = tmp_path / "bad.yaml"
    bad.write_text("must_reach: [unclosed\n")
    with pytest.raises(IntentError, match="malformed YAML"):
        load_intent(bad)
    empty = tmp_path / "empty.yaml"
    empty.write_text("")
    with pytest.raises(IntentError, match="top level"):
        load_intent(empty)


def test_invalid_intent_bodies(tmp_path):
    def write(body: str) -> Path:
        path = tmp_path / "intent.yaml"
        path.write_text(body)
        return path

    with pytest.raises(IntentError, match="missing required key 'version'"):
        load_intent(write("description: x\nmust_reach: []\n"))
    with pytest.raises(IntentError, match="unknown keys"):
        load_intent(
            write(
                "version: 1\nmust_reach:\n"
                "  - id: a\n    src: 192.0.2.10\n    dst: 198.51.100.1\n"
                "    protocol: ICMP\n    start_location: s\n    bogus: 1\n"
            )
        )
    with pytest.raises(IntentError, match="missing required key 'dst'"):
        load_intent(
            write(
                "version: 1\nmust_reach:\n"
                "  - id: a\n    src: 192.0.2.10\n"
                "    protocol: ICMP\n    start_location: s\n"
            )
        )
    with pytest.raises(IntentError, match="must be a list"):
        load_intent(write("version: 1\nmust_reach: {}\n"))
    with pytest.raises(IntentError, match="must be a mapping"):
        load_intent(write("version: 1\nmust_reach:\n  - just-a-string\n"))
    with pytest.raises(IntentError, match="unique"):
        load_intent(
            write(
                "version: 1\nmust_reach:\n"
                "  - id: dup\n    src: 192.0.2.10\n    dst: 198.51.100.1\n"
                "    protocol: ICMP\n    start_location: s\n"
                "must_not_reach:\n"
                "  - id: dup\n    src: 192.0.2.10\n    dst: 198.51.100.1\n"
                "    protocol: ICMP\n    start_location: s\n"
            )
        )


def test_protocol_and_address_rules(tmp_path):
    def write(flows: str) -> Path:
        path = tmp_path / "intent.yaml"
        path.write_text(f"version: 1\n{flows}")
        return path

    base = (
        "must_reach:\n  - id: f\n    src: {src}\n    dst: 198.51.100.1\n"
        "    protocol: {proto}\n    start_location: s{port}\n"
    )
    with pytest.raises(IntentError):
        load_intent(write(base.format(src="not-an-ip", proto="ICMP", port="")))
    with pytest.raises(IntentError):
        load_intent(write(base.format(src="192.0.2.10", proto="GRE", port="")))
    with pytest.raises(IntentError):
        load_intent(write(base.format(src="192.0.2.10", proto="TCP", port="")))
    with pytest.raises(IntentError):
        load_intent(write(base.format(src="192.0.2.10", proto="ICMP", port="\n    dst_port: 80")))
    ok = load_intent(write(base.format(src="192.0.2.10", proto="TCP", port="\n    dst_port: 1433")))
    assert ok.must_reach[0].dst_port == 1433
