"""Deterministic candidate application (Stage C, Phase 4.1).

Copies the pristine proposed snapshot per candidate, renders the validated
operations into the copy, and reports an ``ApplicationResult``. The original
proposed directory is never opened for writing; nothing here contacts
Batfish or any model. Verification, reporting, and CLI wiring are Phase
4.2/4.3 and build on :func:`apply_candidate`.
"""

from __future__ import annotations

import os
import re
import shutil
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path

from netops_lens.acl_parser import AclParseError, parse_acl_rule_line, parse_acl_stanza
from netops_lens.models import (
    AclAction,
    AclDeny,
    AclPermit,
    AddStaticRoute,
    ApplicationResult,
    CandidatePatch,
    FileDiff,
    RemoveAclLine,
    RemoveStaticRoute,
)

_NODE_PATTERN = re.compile(r"[A-Za-z0-9_.-]+")
_ROUTE_OPS = (AddStaticRoute, RemoveStaticRoute)

RouteOp = AddStaticRoute | RemoveStaticRoute
AclRepairOp = RemoveAclLine | AclPermit


class _PatchFailure(Exception):
    """One blocking application cause (surfaced as ``applied=False``)."""


def _fail_result(candidate_id: str, reasons: list[str]) -> ApplicationResult:
    return ApplicationResult(
        candidate_id=candidate_id,
        applied=False,
        reasons=tuple(reasons),
    )


def _revalidate(candidate: CandidatePatch) -> list[str]:
    """Independently re-check the Stage B candidate shape (never agent.py).

    Evidence provenance is Stage B's job and is not rechecked here; this
    gate covers shape plus expected-rule content against the copy later.
    """
    ops = candidate.operations
    if not ops:
        return ["candidate carries no operations"]
    if any(isinstance(op, AclDeny) for op in ops):
        return ["acl_deny operations are unsupported in V1"]
    route_ops = [op for op in ops if isinstance(op, _ROUTE_OPS)]
    remove_ops = [op for op in ops if isinstance(op, RemoveAclLine)]
    permit_ops = [op for op in ops if isinstance(op, AclPermit)]
    if route_ops and (remove_ops or permit_ops):
        return ["mixed route and ACL operations are unsupported in V1"]
    if route_ops:
        return []
    if len(ops) != 2 or len(remove_ops) != 1 or len(permit_ops) != 1:
        return ["V1 ACL repair holds exactly one remove_acl_line and one acl_permit"]
    remove, permit = remove_ops[0], permit_ops[0]
    if (remove.node, remove.acl, remove.sequence_number) != (
        permit.node,
        permit.acl,
        permit.sequence_number,
    ):
        return ["ACL repair operations must share node, ACL, and sequence number"]
    if remove.expected_rule.action != AclAction.DENY:
        return ["remove_acl_line expected_rule must be a deny rule"]
    expected = remove.expected_rule
    if (permit.src, permit.dst, permit.protocol, permit.dst_port) != (
        expected.src,
        expected.dst,
        expected.protocol,
        expected.dst_port,
    ):
        return ["acl_permit must match expected_rule except for the action"]
    return []


def _render_acl_endpoint(endpoint: str) -> str:
    """Render an ``AclEndpoint`` value as IOS match text (wildcard mask)."""
    if endpoint == "any":
        return "any"
    if endpoint.startswith("host "):
        return endpoint
    if "/" in endpoint:
        network = IPv4Network(endpoint, strict=True)
        if network.prefixlen == 32:
            return f"host {network.network_address}"
        return f"{network.network_address} {network.hostmask}"
    return endpoint


def _render_permit_line(permit: AclPermit) -> str:
    """Render the replacement permit content (no indentation, no newline)."""
    src = _render_acl_endpoint(permit.src)
    dst = _render_acl_endpoint(permit.dst)
    return (
        f"{permit.sequence_number} permit {permit.protocol.lower()} "
        f"{src} {dst} eq {permit.dst_port}"
    )


def _parse_route_line(text: str) -> tuple[str, int, str] | None:
    """Parse a stripped ``ip route`` line; ``None`` when malformed.

    The mask must be a dotted-quad IPv4 address (a bare prefix length such
    as ``24`` is rejected) and a contiguous netmask. The network address is
    normalized through the mask, so host-bits lines (``198.51.100.1`` with a
    ``/24`` mask) key identically to the canonical network. Returns the
    semantic key: (network address, prefix length, next hop).
    """
    tokens = text.split()
    if len(tokens) != 5 or tokens[0] != "ip" or tokens[1] != "route":
        return None
    if len(tokens[3].split(".")) != 4:
        return None
    try:
        network = IPv4Network(f"{tokens[2]}/{tokens[3]}", strict=False).network_address
        prefixlen = IPv4Network(f"0.0.0.0/{tokens[3]}").prefixlen
        next_hop = IPv4Address(tokens[4])
    except ValueError:
        return None
    return (str(network), prefixlen, str(next_hop))


def _route_key(prefix: str, next_hop: str) -> tuple[str, int, str]:
    """Semantic key for a candidate CIDR prefix plus next hop."""
    network = IPv4Network(prefix, strict=True)
    return (str(network.network_address), network.prefixlen, next_hop)


def _render_route_line(key: tuple[str, int, str]) -> str:
    network_text, prefixlen, next_hop = key
    mask = str(IPv4Network(f"0.0.0.0/{prefixlen}").netmask)
    return f"ip route {network_text} {mask} {next_hop}"


def _split_lines(raw: bytes) -> tuple[list[str], str, bool]:
    """Split raw file bytes into logical lines.

    Returns (lines, newline, trailing-newline-present). Uniform LF and CRLF
    files round-trip byte-exactly; stray lone newlines inside a CRLF file
    are preserved inside their logical line.
    """
    newline = "\r\n" if b"\r\n" in raw else "\n"
    text = raw.decode("utf-8")
    parts = text.split(newline)
    trailing = parts[-1] == ""
    if trailing:
        parts = parts[:-1]
    return parts, newline, trailing


def _join_lines(lines: list[str], newline: str, trailing: bool) -> bytes:
    return (newline.join(lines) + (newline if trailing else "")).encode("utf-8")


def _route_indices(lines: list[str]) -> list[int]:
    return [i for i, line in enumerate(lines) if line.strip().startswith("ip route")]


def _check_route_lines(lines: list[str]) -> None:
    """Every ``ip route`` line must meet the five-token dialect."""
    for i in _route_indices(lines):
        if _parse_route_line(lines[i].strip()) is None:
            raise _PatchFailure(f"unsupported route line: {lines[i].strip()!r}")


def _apply_route_ops(
    lines: list[str],
    ops: list[RouteOp],
    removed: list[str],
    added: list[str],
) -> None:
    """Mutate ``lines`` in place for the file's route operations."""
    _check_route_lines(lines)
    for op in ops:
        key = _route_key(op.prefix, op.next_hop)
        if isinstance(op, AddStaticRoute):
            for i in _route_indices(lines):
                parsed = _parse_route_line(lines[i].strip())
                if parsed is None:
                    raise _PatchFailure(f"unsupported route line: {lines[i].strip()!r}")
                if parsed == key:
                    raise _PatchFailure(f"route already exists: {_render_route_line(key)}")
            rendered = _render_route_line(key)
            indices = _route_indices(lines)
            if indices:
                lines.insert(indices[-1] + 1, rendered)
            else:
                tail = len(lines) - 1
                while tail >= 0 and not lines[tail].strip():
                    tail -= 1
                if tail >= 0 and lines[tail].strip() == "end":
                    lines.insert(tail, rendered)
                else:
                    lines.append(rendered)
            added.append(rendered)
        else:
            matches: list[int] = []
            for i in _route_indices(lines):
                parsed = _parse_route_line(lines[i].strip())
                if parsed is None:
                    raise _PatchFailure(f"unsupported route line: {lines[i].strip()!r}")
                if parsed == key:
                    matches.append(i)
            if len(matches) != 1:
                found = "none" if not matches else "multiple"
                raise _PatchFailure(
                    f"route removal needs exactly one match, found {found}: "
                    f"{op.prefix} via {op.next_hop}"
                )
            removed.append(lines[matches[0]].strip())
            del lines[matches[0]]


def _apply_acl_splice(
    lines: list[str],
    newline: str,
    remove: RemoveAclLine,
    permit: AclPermit,
    removed: list[str],
    added: list[str],
) -> None:
    """Delete the validated deny line; insert the permit at the same index."""
    stanza_text = newline.join(lines)
    if stanza_text.splitlines() != lines:
        raise _PatchFailure("unsupported line-ending mixture in ACL file")
    try:
        stanza = parse_acl_stanza(stanza_text, remove.acl)
    except AclParseError as exc:
        raise _PatchFailure(str(exc)) from exc
    targets = [rule for rule in stanza.rules if rule.sequence_number == remove.sequence_number]
    if len(targets) != 1:
        raise _PatchFailure(
            f"ACL {remove.acl!r} has no unique rule at sequence {remove.sequence_number}"
        )
    if targets[0].rule != remove.expected_rule:
        raise _PatchFailure(
            f"remove_acl_line expected-rule mismatch at sequence {remove.sequence_number}"
        )
    index = targets[0].line_index
    old = lines[index]
    indent = old[: len(old) - len(old.lstrip())]
    permit_text = _render_permit_line(permit)
    lines[index] = indent + permit_text
    removed.append(old.strip())
    added.append(permit_text)


def _resolve_target_file(candidate_dir: Path, node: str) -> Path:
    """Resolve ``configs/<node>.cfg`` inside the candidate copy, safely."""
    if _NODE_PATTERN.fullmatch(node) is None or node in (".", ".."):
        raise _PatchFailure(f"invalid node name: {node!r}")
    configs_dir = (candidate_dir / "configs").resolve()
    if configs_dir != candidate_dir and candidate_dir not in configs_dir.parents:
        raise _PatchFailure("node config escapes candidate copy")
    target = (configs_dir / f"{node}.cfg").resolve()
    if target.parent != configs_dir or not target.is_file():
        raise _PatchFailure(f"config not found for node {node!r}")
    return target


def _create_candidate_copy(
    proposed_dir: str | Path, ephemeral_root: str | Path, candidate_id: str
) -> Path:
    """Copy the pristine proposed snapshot to a fresh candidate directory.

    Performs every confinement check before copying: both inputs must be
    existing directories, they must not overlap in either direction, and the
    candidate path must sit strictly under the ephemeral root and not
    already exist (dangling symlinks refuse via ``lexists``). Returns the
    candidate directory. Failures raise ``_PatchFailure`` with generic,
    path-free reasons.
    """
    try:
        root = Path(ephemeral_root).resolve()
        root_is_dir = root.is_dir()
        proposed = Path(proposed_dir).resolve()
        proposed_is_dir = proposed.is_dir()
    except OSError:
        raise _PatchFailure("cannot resolve candidate paths") from None
    if not root_is_dir:
        raise _PatchFailure("ephemeral root is not a directory")
    if not proposed_is_dir:
        raise _PatchFailure("proposed directory not found")
    if root == proposed or root in proposed.parents or proposed in root.parents:
        raise _PatchFailure("ephemeral root and proposed directory must not overlap")
    raw_candidate = root / f"candidate-{candidate_id}"
    if os.path.lexists(raw_candidate):
        raise _PatchFailure("candidate directory already exists")
    candidate_dir = raw_candidate.resolve()
    if candidate_dir == root or root not in candidate_dir.parents:
        raise _PatchFailure("candidate directory escapes ephemeral root")
    already_there = os.path.lexists(raw_candidate)
    try:
        shutil.copytree(proposed, candidate_dir)
    except OSError:
        # Pre-existing paths are refused above, so a directory present here
        # was created by this attempt: remove only that partial copy, never
        # a directory that predates this call.
        if not already_there and os.path.lexists(candidate_dir):
            shutil.rmtree(candidate_dir, ignore_errors=True)
        raise _PatchFailure("cannot copy proposed snapshot") from None
    return candidate_dir


def _verify_written_file(relpath: str, raw: bytes, ops: list[RouteOp | AclRepairOp]) -> None:
    """Re-parse a written file and confirm the intended mutation landed."""
    lines, newline, _ = _split_lines(raw)
    route_ops = [op for op in ops if isinstance(op, _ROUTE_OPS)]
    acl_ops = [op for op in ops if isinstance(op, (RemoveAclLine, AclPermit))]
    if acl_ops:
        remove = next(op for op in acl_ops if isinstance(op, RemoveAclLine))
        permit = next(op for op in acl_ops if isinstance(op, AclPermit))
        stanza_text = newline.join(lines)
        try:
            stanza = parse_acl_stanza(stanza_text, remove.acl)
        except AclParseError as exc:
            raise _PatchFailure(f"written ACL file fails re-parse: {exc}") from exc
        targets = [r for r in stanza.rules if r.sequence_number == remove.sequence_number]
        if len(targets) != 1:
            raise _PatchFailure("written ACL file lost the repaired sequence")
        try:
            rendered = parse_acl_rule_line(
                f"{permit.sequence_number} permit {permit.protocol} "
                f"{permit.src} {permit.dst} eq {permit.dst_port}"
            )
        except AclParseError as exc:
            raise _PatchFailure(f"written ACL file holds an unparsable permit: {exc}") from exc
        if targets[0].rule != rendered.rule:
            raise _PatchFailure("written ACL file does not hold the repaired permit")
    if route_ops:
        _check_route_lines(lines)
        keys = [_parse_route_line(lines[i].strip()) for i in _route_indices(lines)]
        for op in route_ops:
            key = _route_key(op.prefix, op.next_hop)
            if isinstance(op, AddStaticRoute):
                if key not in keys:
                    raise _PatchFailure(f"written route file lost added route {op.prefix}")
            elif key in keys:
                raise _PatchFailure(f"written route file still holds removed route {op.prefix}")


def apply_candidate(
    candidate: CandidatePatch,
    *,
    proposed_dir: str | Path,
    ephemeral_root: str | Path,
    keep_failed_dirs: bool = False,
) -> tuple[ApplicationResult, Path | None]:
    """Apply one candidate to a fresh disposable copy of proposed.

    Returns ``(result, candidate_dir)`` on success; on any failure returns
    ``(result with applied=False, None)`` and removes the candidate
    directory unless ``keep_failed_dirs`` is set. The pristine proposed
    directory is never opened for writing. A failed application is never
    returned with a path and is never loadable as a completed candidate.
    """
    candidate_id = candidate.candidate_id
    shape_reasons = _revalidate(candidate)
    if shape_reasons:
        return _fail_result(candidate_id, shape_reasons), None

    try:
        candidate_dir = _create_candidate_copy(proposed_dir, ephemeral_root, candidate_id)
    except _PatchFailure as exc:
        return _fail_result(candidate_id, [str(exc)]), None
    created = True
    try:
        by_node: dict[str, list[RouteOp | AclRepairOp]] = {}
        for op in candidate.operations:
            if isinstance(op, AclDeny):
                raise _PatchFailure("acl_deny operations are unsupported in V1")
            by_node.setdefault(op.node, []).append(op)

        targets: list[tuple[str, Path, list[RouteOp | AclRepairOp]]] = []
        for node, node_ops in by_node.items():
            target = _resolve_target_file(candidate_dir, node)
            relpath = target.relative_to(candidate_dir).as_posix()
            targets.append((relpath, target, node_ops))

        rendered: list[tuple[Path, bytes, FileDiff, list[RouteOp | AclRepairOp]]] = []
        for relpath, target, node_ops in targets:
            raw = target.read_bytes()
            lines, newline, trailing = _split_lines(raw)
            removed: list[str] = []
            added: list[str] = []
            route_ops = [op for op in node_ops if isinstance(op, _ROUTE_OPS)]
            acl_remove = [op for op in node_ops if isinstance(op, RemoveAclLine)]
            acl_permit = [op for op in node_ops if isinstance(op, AclPermit)]
            if acl_remove or acl_permit:
                if len(acl_remove) != 1 or len(acl_permit) != 1:
                    raise _PatchFailure(
                        "V1 ACL repair holds exactly one remove_acl_line and one acl_permit"
                    )
                _apply_acl_splice(lines, newline, acl_remove[0], acl_permit[0], removed, added)
            if route_ops:
                _apply_route_ops(lines, route_ops, removed, added)
            new_raw = _join_lines(lines, newline, trailing)
            diff = FileDiff(file=relpath, removed=tuple(removed), added=tuple(added))
            rendered.append((target, new_raw, diff, node_ops))

        for target, new_raw, diff, node_ops in rendered:
            tmp = target.with_name(target.name + ".tmp-patch")
            tmp.write_bytes(new_raw)
            os.replace(tmp, target)

        for (relpath, _, node_ops), (_, new_raw, _, _) in zip(targets, rendered):
            _verify_written_file(relpath, new_raw, node_ops)

        diffs = tuple(diff for _, _, diff, _ in rendered)
        result = ApplicationResult(
            candidate_id=candidate_id,
            applied=True,
            changed_files=tuple(diff.file for diff in diffs),
            diff=diffs,
        )
        return result, candidate_dir
    except _PatchFailure as exc:
        result = _fail_result(candidate_id, [str(exc)])
    except Exception as exc:  # never raise across the boundary
        result = _fail_result(candidate_id, [f"unexpected application error: {exc}"])

    if created and not keep_failed_dirs:
        shutil.rmtree(candidate_dir, ignore_errors=True)
    return result, None
