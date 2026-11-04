"""Unit tests for the narrow IOS extended-ACL parser (no Batfish, no Docker)."""

from __future__ import annotations

from pathlib import Path

import pytest

from netops_lens.acl_parser import (
    AclParseError,
    load_node_acl,
    parse_acl_rule_line,
    parse_acl_stanza,
    parse_extended_acl,
)

REPO_ROOT = Path(__file__).resolve().parent.parent

ACL_BASELINE_R1 = (REPO_ROOT / "lab/scenarios/acl_blocks_db/baseline/configs/r1.cfg").read_text()
ACL_PROPOSED_R1 = (REPO_ROOT / "lab/scenarios/acl_blocks_db/proposed/configs/r1.cfg").read_text()


def test_parse_fixture_baseline_rules():
    rules = parse_extended_acl(ACL_BASELINE_R1, "DB-FILTER")
    assert [(r.sequence_number, r.rule.action.value) for r in rules] == [
        (10, "permit"),
        (20, "deny"),
    ]
    assert rules[0].rule.dst_port == 1433
    assert rules[1].rule.dst_port == 22
    assert rules[0].rule.src == "192.0.2.0/24"
    assert rules[0].rule.dst == "198.51.100.0/24"
    assert rules[0].raw_line == ("10 permit tcp 192.0.2.0 0.0.0.255 198.51.100.0 0.0.0.255 eq 1433")


def test_parse_fixture_proposed_seq10_is_deny():
    rules = parse_extended_acl(ACL_PROPOSED_R1, "DB-FILTER")
    assert [(r.sequence_number, r.rule.action.value) for r in rules] == [
        (10, "deny"),
        (20, "deny"),
    ]
    assert rules[0].raw_line == ("10 deny tcp 192.0.2.0 0.0.0.255 198.51.100.0 0.0.0.255 eq 1433")


def test_load_node_acl_reads_snapshot_file():
    rules = load_node_acl(REPO_ROOT / "lab/scenarios/acl_blocks_db/baseline", "r1", "DB-FILTER")
    assert [r.sequence_number for r in rules] == [10, 20]
    with pytest.raises(AclParseError):
        load_node_acl(REPO_ROOT / "lab/scenarios/acl_blocks_db/baseline", "r9", "DB-FILTER")
    with pytest.raises(AclParseError):
        load_node_acl(REPO_ROOT / "lab/scenarios/acl_blocks_db/baseline", "r1", "NOPE")


def _snapshot() -> Path:
    return REPO_ROOT / "lab/scenarios/acl_blocks_db/baseline"


def test_load_node_acl_rejects_traversal():
    for evil in ("../r1", "..", ".", "r1/../../r1", "sub/dir", "/etc/passwd", "r1.cfg", ""):
        with pytest.raises(AclParseError):
            load_node_acl(_snapshot(), evil, "DB-FILTER")


def test_load_node_acl_rejects_absolute_and_nested_paths(tmp_path: Path):
    outside = tmp_path / "evil.cfg"
    outside.write_text("hostname evil\n")
    with pytest.raises(AclParseError):
        load_node_acl(_snapshot(), str(outside), "DB-FILTER")
    with pytest.raises(AclParseError):
        load_node_acl(_snapshot(), "configs/r1", "DB-FILTER")


def test_load_node_acl_unknown_node_is_not_a_filesystem_probe():
    # r9 is a valid name shape but absent: a clean "not found", and the
    # error must not echo an attacker-controlled filesystem path.
    with pytest.raises(AclParseError) as excinfo:
        load_node_acl(_snapshot(), "r9", "DB-FILTER")
    assert "r9.cfg" not in str(excinfo.value)
    assert ".." not in str(excinfo.value)


def test_load_node_acl_valid_nodes():
    base = _snapshot()
    first = load_node_acl(base, "r1", "DB-FILTER")
    assert [r.sequence_number for r in first] == [10, 20]
    if (base / "configs" / "r2.cfg").is_file():
        try:
            assert isinstance(load_node_acl(base, "r2", "DB-FILTER"), tuple)
        except AclParseError:
            pass  # valid name, clean scoping; stanza simply absent on r2


def test_parse_endpoints_and_protocols():
    assert parse_acl_rule_line("10 permit ip any any").rule.protocol == "ip"
    assert parse_acl_rule_line("5 deny tcp host 192.0.2.10 any eq 22").rule.src == "host 192.0.2.10"
    assert (
        parse_acl_rule_line("7 permit udp 192.0.2.0/24 host 198.51.100.1").rule.dst
        == "host 198.51.100.1"
    )


def test_malformed_acl_input_fails_explicitly():
    bad_lines = [
        "permit tcp any any",  # unnumbered
        "10 permit tcp any any eq 1 range 2",  # unsupported range
        "10 permit tcp any any log",  # unsupported trailing keyword
        "10 permit gre any any",  # unsupported protocol
        "10 permit tcp any",  # missing destination
        "10 permit tcp 192.0.2.0 0.0.255.0 any",  # non-contiguous mask
        "10 remark block db admin",  # remark carries no match
        "10 permit tcp any any eq notaport",
    ]
    for bad in bad_lines:
        with pytest.raises(AclParseError):
            parse_acl_rule_line(bad)
    with pytest.raises(AclParseError):
        parse_acl_rule_line("   ")


def test_duplicate_sequence_rejected():
    config = (
        "ip access-list extended DB-FILTER\n"
        " 10 permit tcp any any eq 1433\n"
        " 10 deny tcp any any eq 22\n"
    )
    with pytest.raises(AclParseError, match="duplicate sequence 10"):
        parse_extended_acl(config, "DB-FILTER")


def test_stanza_span_and_line_indices_on_fixture():
    stanza = parse_acl_stanza(ACL_PROPOSED_R1, "DB-FILTER")
    assert stanza.name == "DB-FILTER"
    lines = ACL_PROPOSED_R1.splitlines()
    assert lines[stanza.header_index].strip() == "ip access-list extended DB-FILTER"
    assert all(
        line == "" or line[:1].isspace()
        for line in lines[stanza.header_index + 1 : stanza.end_index]
    )
    assert [r.sequence_number for r in stanza.rules] == [10, 20]
    for rule in stanza.rules:
        assert lines[rule.line_index].strip() == rule.raw_line
    assert lines[stanza.end_index].strip() == "!"


def test_stanza_span_skips_blank_lines_but_keeps_them():
    config = (
        "ip access-list extended DB-FILTER\n"
        "\n"
        " 10 permit tcp any any eq 1433\n"
        "   \n"
        " 20 deny tcp any any eq 22\n"
        "!\n"
    )
    stanza = parse_acl_stanza(config, "DB-FILTER")
    assert stanza.header_index == 0
    assert stanza.end_index == 5
    assert [r.line_index for r in stanza.rules] == [2, 4]


def test_stanza_span_ends_at_end_or_bare_line():
    for terminator in ("end", "interface GigabitEthernet0/0"):
        config = (
            "ip access-list extended DB-FILTER\n"
            " 10 permit tcp any any eq 1433\n"
            f"{terminator}\n"
        )
        stanza = parse_acl_stanza(config, "DB-FILTER")
        assert stanza.end_index == 2
        assert [r.sequence_number for r in stanza.rules] == [10]


def test_stanza_zero_or_multiple_names_rejected():
    with pytest.raises(AclParseError, match="not found"):
        parse_acl_stanza("hostname r1\n!\nend\n", "DB-FILTER")
    doubled = (
        "ip access-list extended DB-FILTER\n"
        " 10 permit tcp any any eq 1433\n"
        "!\n"
        "ip access-list extended DB-FILTER\n"
        " 20 deny tcp any any eq 22\n"
        "!\n"
    )
    with pytest.raises(AclParseError, match="multiple"):
        parse_acl_stanza(doubled, "DB-FILTER")
    with pytest.raises(AclParseError, match="multiple"):
        parse_extended_acl(doubled, "DB-FILTER")


def test_stanza_remark_and_unnumbered_lines_rejected():
    remark = (
        "ip access-list extended DB-FILTER\n"
        " 10 permit tcp any any eq 1433\n"
        " remark db block\n"
        "!\n"
    )
    with pytest.raises(AclParseError, match="remark db block"):
        parse_acl_stanza(remark, "DB-FILTER")
    unnumbered = (
        "ip access-list extended DB-FILTER\n"
        " permit tcp any any\n"
        "!\n"
    )
    with pytest.raises(AclParseError, match="without sequence number"):
        parse_acl_stanza(unnumbered, "DB-FILTER")


def test_standalone_rule_line_index_is_minus_one():
    assert parse_acl_rule_line("10 permit tcp any any eq 1433").line_index == -1


def test_missing_or_empty_stanza_rejected():
    with pytest.raises(AclParseError, match="not found"):
        parse_extended_acl("hostname r1\n!\nend\n", "DB-FILTER")
    with pytest.raises(AclParseError, match="no parseable rules"):
        parse_extended_acl("ip access-list extended DB-FILTER\n!\n", "DB-FILTER")
