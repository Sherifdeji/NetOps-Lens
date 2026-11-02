"""Unit tests for the narrow IOS extended-ACL parser (no Batfish, no Docker)."""

from __future__ import annotations

from pathlib import Path

import pytest

from netops_lens.acl_parser import (
    AclParseError,
    load_node_acl,
    parse_acl_rule_line,
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


def test_missing_or_empty_stanza_rejected():
    with pytest.raises(AclParseError, match="not found"):
        parse_extended_acl("hostname r1\n!\nend\n", "DB-FILTER")
    with pytest.raises(AclParseError, match="no parseable rules"):
        parse_extended_acl("ip access-list extended DB-FILTER\n!\n", "DB-FILTER")
