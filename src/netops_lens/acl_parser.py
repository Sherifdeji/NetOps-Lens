"""Narrow parser for sequence-numbered Cisco IOS extended ACLs.

Scoped to the V1 fixture vocabulary only: ``[seq] permit|deny <protocol>
<src> <dst> [eq <port>]`` where endpoints are ``any``, ``host <ip>``,
a plain address, CIDR, or an address + contiguous wildcard mask. Everything
else (remarks, ``range``/``lt``/``gt``/``neq`` ports, ``log``, ``established``,
non-contiguous masks, unnumbered lines, duplicate sequences) is rejected
with an error naming the offending line — lines are never silently omitted.

Wildcard masks normalize to CIDR (``192.0.2.0 0.0.0.255`` ->
``192.0.2.0/24``) so output fits the ``AclEndpoint`` contract; the original
text is preserved verbatim in ``raw_line``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path

from pydantic import ValidationError

from netops_lens.models import AclAction, AclRule


class AclParseError(Exception):
    """A stanza or line this parser cannot model exactly."""


@dataclass(frozen=True)
class ParsedAclRule:
    sequence_number: int
    rule: AclRule
    raw_line: str


def _wildcard_to_prefixlen(address: str, wildcard: str, raw_line: str) -> str:
    try:
        wild = int(IPv4Address(wildcard))
    except ValueError as exc:
        raise AclParseError(f"bad wildcard mask in {raw_line!r}") from exc
    if (wild + 1) & wild != 0:
        raise AclParseError(f"non-contiguous wildcard mask in {raw_line!r}")
    prefixlen = 32 - wild.bit_length()
    try:
        return str(IPv4Network(f"{address}/{prefixlen}", strict=False))
    except ValueError as exc:
        raise AclParseError(f"bad network in {raw_line!r}") from exc


def _is_ipv4_token(token: str) -> bool:
    try:
        IPv4Address(token)
        return True
    except ValueError:
        return False


def parse_acl_rule_line(raw_line: str) -> ParsedAclRule:
    """Parse one sequence-numbered extended ACL rule line."""
    line = raw_line.strip()
    if not line:
        raise AclParseError("empty ACL line")
    tokens = line.split()
    if not tokens[0].isdigit():
        raise AclParseError(f"ACL line without sequence number: {raw_line!r}")
    sequence_number = int(tokens[0])
    rest = tokens[1:]
    if len(rest) < 4 or rest[0] not in ("permit", "deny"):
        raise AclParseError(f"ACL line without permit/deny action: {raw_line!r}")
    action = AclAction(rest[0])
    protocol = rest[1]
    endpoint_tokens = rest[2:]

    def take_endpoint(tokens: list[str]) -> tuple[str, list[str]]:
        if not tokens:
            raise AclParseError(f"missing address in {raw_line!r}")
        if tokens[0].lower() == "any":
            return "any", tokens[1:]
        if tokens[0].lower() == "host":
            if len(tokens) < 2 or not _is_ipv4_token(tokens[1]):
                raise AclParseError(f"bad host address in {raw_line!r}")
            return f"host {tokens[1]}", tokens[2:]
        if "/" in tokens[0]:
            return tokens[0], tokens[1:]
        if not _is_ipv4_token(tokens[0]):
            raise AclParseError(f"bad address in {raw_line!r}")
        if len(tokens) >= 2 and _is_ipv4_token(tokens[1]):
            return _wildcard_to_prefixlen(tokens[0], tokens[1], raw_line), tokens[2:]
        return tokens[0], tokens[1:]

    src, remaining = take_endpoint(endpoint_tokens)
    dst, remaining = take_endpoint(remaining)

    dst_port: int | None = None
    if remaining:
        if len(remaining) != 2 or remaining[0].lower() != "eq":
            raise AclParseError(f"unsupported port/match syntax in {raw_line!r}")
        try:
            dst_port = int(remaining[1])
        except ValueError as exc:
            raise AclParseError(f"bad destination port in {raw_line!r}") from exc

    try:
        rule = AclRule(action=action, src=src, dst=dst, protocol=protocol, dst_port=dst_port)
    except ValidationError as exc:
        detail = exc.errors()[0]["msg"]
        raise AclParseError(f"invalid rule content in {raw_line!r}: {detail}") from exc
    return ParsedAclRule(sequence_number=sequence_number, rule=rule, raw_line=line)


def parse_extended_acl(config_text: str, acl_name: str) -> tuple[ParsedAclRule, ...]:
    """Parse the named extended ACL stanza from one device config."""
    lines = config_text.splitlines()
    header = f"ip access-list extended {acl_name}"
    start: int | None = None
    for i, line in enumerate(lines):
        if line.strip() == header:
            start = i
            break
    if start is None:
        raise AclParseError(f"ACL {acl_name!r} stanza not found")

    rules: list[ParsedAclRule] = []
    seen: set[int] = set()
    for line in lines[start + 1 :]:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped == "!" or stripped == "end" or not line[:1].isspace():
            break
        parsed = parse_acl_rule_line(stripped)
        if parsed.sequence_number in seen:
            raise AclParseError(f"duplicate sequence {parsed.sequence_number} in ACL {acl_name!r}")
        seen.add(parsed.sequence_number)
        rules.append(parsed)
    if not rules:
        raise AclParseError(f"ACL {acl_name!r} has no parseable rules")
    return tuple(rules)


def load_node_acl(snapshot_dir: str | Path, node: str, acl_name: str) -> tuple[ParsedAclRule, ...]:
    """Read ``<node>.cfg`` inside a snapshot dir and parse one ACL stanza.

    F-08: a model-supplied node name must never become an arbitrary
    filesystem path. The name is restricted to a flat filename vocabulary
    (no separators, no ``.``/``..``), and the resolved file must remain
    inside the snapshot's ``configs/`` directory. Nothing outside the
    approved snapshot directory is ever opened.
    """
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", node) or node in (".", ".."):
        raise AclParseError(f"invalid node name: {node!r}")
    configs_dir = Path(snapshot_dir) / "configs"
    config_path = (configs_dir / f"{node}.cfg").resolve()
    if config_path.parent != configs_dir.resolve() or not config_path.is_file():
        raise AclParseError(f"config not found for node {node!r}")
    return parse_extended_acl(config_path.read_text(), acl_name)
