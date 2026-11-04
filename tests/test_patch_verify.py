"""Application-scope tests for patch.py (no Batfish, no model calls).

Snapshot dirs are built under tmp_path with the ephemeral root kept
disjoint from the proposed source (overlap is refused); lab fixtures are
used as read-only sources (copied, never modified).
"""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

from netops_lens.models import (
    AclDeny,
    AclPermit,
    AclRule,
    AddStaticRoute,
    ApplicationResult,
    CandidatePatch,
    RemoveAclLine,
    RemoveStaticRoute,
)
from netops_lens.patch import _create_candidate_copy, apply_candidate

REPO_ROOT = Path(__file__).resolve().parent.parent
ACL_PROPOSED = REPO_ROOT / "lab/scenarios/acl_blocks_db/proposed"
REMOVED_ROUTE_PROPOSED = REPO_ROOT / "lab/proposed"

DENY_10 = "10 deny tcp 192.0.2.0 0.0.0.255 198.51.100.0 0.0.0.255 eq 1433"
PERMIT_10 = "10 permit tcp 192.0.2.0 0.0.0.255 198.51.100.0 0.0.0.255 eq 1433"
SEQ_20 = "20 deny tcp 192.0.2.0 0.0.0.255 198.51.100.0 0.0.0.255 eq 22"
DB_ROUTE = "ip route 198.51.100.0 255.255.255.0 10.0.12.2"


def _snapshot_copy(src: Path, parent: Path, name: str = "proposed") -> Path:
    dest = parent / name
    shutil.copytree(src, dest)
    return dest


def _stage(parent: Path, fixture: Path) -> tuple[Path, Path]:
    """Copy a fixture and make a disjoint ephemeral root under ``parent``."""
    src = _snapshot_copy(fixture, parent)
    root = parent / "runs"
    root.mkdir()
    return src, root


def _hash_tree(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _expected_rule(**overrides: object) -> AclRule:
    fields: dict[str, object] = {
        "action": "deny",
        "src": "192.0.2.0/24",
        "dst": "198.51.100.0/24",
        "protocol": "tcp",
        "dst_port": 1433,
    }
    fields.update(overrides)
    return AclRule(**fields)  # type: ignore[arg-type]


def _acl_repair_candidate(
    candidate_id: str = "c-01",
    seq: int = 10,
    expected: AclRule | None = None,
    node: str = "r1",
    acl: str = "DB-FILTER",
    src: str = "192.0.2.0/24",
) -> CandidatePatch:
    rule = expected if expected is not None else _expected_rule(src=src)
    return CandidatePatch(
        candidate_id=candidate_id,  # type: ignore[arg-type]
        rationale="test ACL repair",
        operations=[
            RemoveAclLine(
                op="remove_acl_line", node=node, acl=acl, sequence_number=seq,
                expected_rule=rule,
            ),
            AclPermit(
                op="acl_permit", node=node, acl=acl, sequence_number=seq,
                src=src, dst="198.51.100.0/24", protocol="tcp", dst_port=1433,
            ),
        ],
        target_flow_ids=["app-to-db-authorized"],
    )


def _route_candidate(
    candidate_id: str = "c-01",
    prefix: str = "198.51.100.0/24",
    next_hop: str = "10.0.12.2",
    node: str = "r1",
    remove: bool = False,
) -> CandidatePatch:
    if remove:
        op = RemoveStaticRoute(
            op="remove_static_route", node=node, prefix=prefix, next_hop=next_hop
        )
    else:
        op = AddStaticRoute(
            op="add_static_route", node=node, prefix=prefix, next_hop=next_hop
        )
    return CandidatePatch(
        candidate_id=candidate_id,  # type: ignore[arg-type]
        rationale="test route change",
        operations=[op],
        target_flow_ids=["app-to-db-icmp"],
    )


def _write_snapshot(root: Path, name: str, files: dict[str, str]) -> Path:
    snap = root / name
    configs = snap / "configs"
    configs.mkdir(parents=True)
    for relpath, text in files.items():
        (snap / relpath).write_text(text)
    assert configs.is_dir()
    return snap


def test_acl_repair_lf_is_byte_exact(tmp_path: Path):
    src, root = _stage(tmp_path, ACL_PROPOSED)
    source_text = (src / "configs" / "r1.cfg").read_text()
    assert f" {DENY_10}\n" in source_text

    result, path = apply_candidate(
        _acl_repair_candidate(), proposed_dir=src, ephemeral_root=root
    )

    assert result.applied is True
    assert result.reasons == ()
    assert path is not None and path.is_dir()
    written = (path / "configs" / "r1.cfg").read_text()
    assert written == source_text.replace(f" {DENY_10}\n", f" {PERMIT_10}\n", 1)
    lines = written.splitlines()
    assert f" {PERMIT_10}" in lines
    assert lines.index(f" {PERMIT_10}") < lines.index(f" {SEQ_20}")
    assert result.changed_files == ("configs/r1.cfg",)
    assert len(result.diff) == 1
    diff = result.diff[0]
    assert diff.file == "configs/r1.cfg"
    assert diff.removed == (DENY_10,)
    assert diff.added == (PERMIT_10,)
    assert ApplicationResult.model_validate(result.model_dump()) == result


def test_acl_repair_crlf_preserves_newlines(tmp_path: Path):
    src, root = _stage(tmp_path, ACL_PROPOSED)
    raw_source = (src / "configs" / "r1.cfg").read_bytes()
    assert b"\r" not in raw_source
    crlf_source = raw_source.replace(b"\n", b"\r\n")
    (src / "configs" / "r1.cfg").write_bytes(crlf_source)

    result, path = apply_candidate(
        _acl_repair_candidate(), proposed_dir=src, ephemeral_root=root
    )

    assert result.applied is True
    assert path is not None
    written = (path / "configs" / "r1.cfg").read_bytes()
    assert written == crlf_source.replace(
        f" {DENY_10}\r\n".encode(), f" {PERMIT_10}\r\n".encode(), 1
    )
    assert b"\r\n" in written
    assert b"\n" not in written.replace(b"\r\n", b"")


def test_acl_wrong_sequence_fails_and_cleans_up(tmp_path: Path):
    src, root = _stage(tmp_path, ACL_PROPOSED)
    result, path = apply_candidate(
        _acl_repair_candidate(candidate_id="c-02", seq=99),
        proposed_dir=src, ephemeral_root=root,
    )
    assert result.applied is False
    assert path is None
    assert any("99" in reason for reason in result.reasons)
    assert not (root / "candidate-c-02").exists()


def test_acl_wrong_expected_rule_names_sequence(tmp_path: Path):
    # Shape-valid (permit matches expected_rule) but the file holds /24:
    # the splice check must fail naming sequence 10.
    src, root = _stage(tmp_path, ACL_PROPOSED)
    candidate = _acl_repair_candidate(src="192.0.2.0/25")
    result, path = apply_candidate(
        candidate, proposed_dir=src, ephemeral_root=root
    )
    assert result.applied is False
    assert path is None
    assert any("10" in reason for reason in result.reasons)
    assert not (root / "candidate-c-01").exists()


def test_revalidation_rejects_bad_shapes(tmp_path: Path):
    src, root = _stage(tmp_path, ACL_PROPOSED)
    deny_only = CandidatePatch(
        candidate_id="c-01",  # type: ignore[arg-type]
        rationale="deny",
        operations=[
            AclDeny(
                op="acl_deny", node="r1", acl="DB-FILTER", sequence_number=20,
                src="192.0.2.0/24", dst="198.51.100.0/24",
                protocol="tcp", dst_port=22,
            )
        ],
        target_flow_ids=["app-to-db-unauthorized"],
    )
    mixed = CandidatePatch(
        candidate_id="c-02",  # type: ignore[arg-type]
        rationale="mixed",
        operations=[
            AddStaticRoute(
                op="add_static_route", node="r1", prefix="198.51.100.0/24",
                next_hop="10.0.12.2",
            ),
            *(_acl_repair_candidate(candidate_id="c-99").operations),
        ],
        target_flow_ids=["app-to-db-icmp"],
    )
    permit_only = CandidatePatch(
        candidate_id="c-03",  # type: ignore[arg-type]
        rationale="permit without remove",
        operations=[
            AclPermit(
                op="acl_permit", node="r1", acl="DB-FILTER", sequence_number=10,
                src="192.0.2.0/24", dst="198.51.100.0/24",
                protocol="tcp", dst_port=1433,
            )
        ],
        target_flow_ids=["app-to-db-authorized"],
    )
    for candidate, needle in (
        (deny_only, "acl_deny"),
        (mixed, "mixed"),
        (permit_only, "exactly one remove_acl_line"),
    ):
        result, path = apply_candidate(
            candidate, proposed_dir=src, ephemeral_root=root
        )
        assert result.applied is False, candidate.candidate_id
        assert path is None
        assert any(needle in reason for reason in result.reasons)
        assert not (root / f"candidate-{candidate.candidate_id}").exists()


def _acl_snapshot_with_r1(parent: Path, r1_text: str) -> Path:
    return _write_snapshot(
        parent,
        "proposed",
        {
            "configs/r1.cfg": r1_text,
            "configs/r2.cfg": "hostname r2\n!\nend\n",
        },
    )


def test_multi_stanza_same_name_rejected_file_unchanged(tmp_path: Path):
    base = (ACL_PROPOSED / "configs" / "r1.cfg").read_text()
    doubled = base + "\nip access-list extended DB-FILTER\n 30 permit tcp any any eq 80\n"
    src = _acl_snapshot_with_r1(tmp_path, doubled)
    root = tmp_path / "runs"
    root.mkdir()
    result, path = apply_candidate(
        _acl_repair_candidate(), proposed_dir=src, ephemeral_root=root,
        keep_failed_dirs=True,
    )
    assert result.applied is False
    assert path is None
    assert any("multiple" in reason for reason in result.reasons)
    leftover = root / "candidate-c-01" / "configs" / "r1.cfg"
    assert leftover.read_text() == doubled


def test_remark_inside_stanza_rejected_file_unchanged(tmp_path: Path):
    base = (ACL_PROPOSED / "configs" / "r1.cfg").read_text()
    remarked = base.replace(
        f" {DENY_10}\n", " remark db block\n" + f" {DENY_10}\n", 1
    )
    src = _acl_snapshot_with_r1(tmp_path, remarked)
    root = tmp_path / "runs"
    root.mkdir()
    result, path = apply_candidate(
        _acl_repair_candidate(), proposed_dir=src, ephemeral_root=root,
        keep_failed_dirs=True,
    )
    assert result.applied is False
    assert path is None
    leftover = root / "candidate-c-01" / "configs" / "r1.cfg"
    assert leftover.read_text() == remarked


def test_permit_host_endpoint_renders_host_form(tmp_path: Path):
    r1 = (
        "version 15.2\nhostname r1\n!\n"
        "ip access-list extended DB-FILTER\n"
        " 10 deny tcp host 192.0.2.10 198.51.100.0 0.0.0.255 eq 1433\n"
        " 20 deny tcp any any eq 22\n"
        "!\nend\n"
    )
    src = _acl_snapshot_with_r1(tmp_path, r1)
    root = tmp_path / "runs"
    root.mkdir()
    result, path = apply_candidate(
        _acl_repair_candidate(src="host 192.0.2.10"),
        proposed_dir=src, ephemeral_root=root,
    )
    assert result.applied is True
    assert path is not None
    written = (path / "configs" / "r1.cfg").read_text()
    assert " 10 permit tcp host 192.0.2.10 198.51.100.0 0.0.0.255 eq 1433" in (
        written.splitlines()
    )


def test_route_add_renders_exact_line(tmp_path: Path):
    src, root = _stage(tmp_path, REMOVED_ROUTE_PROPOSED)
    result, path = apply_candidate(
        _route_candidate(), proposed_dir=src, ephemeral_root=root
    )
    assert result.applied is True
    assert path is not None
    lines = (path / "configs" / "r1.cfg").read_text().splitlines()
    assert DB_ROUTE in lines
    assert lines.index(DB_ROUTE) < lines.index("end")
    # The proposed r1.cfg carries no other route; the line lands before end.
    assert lines[-1] == "end"
    assert result.changed_files == ("configs/r1.cfg",)
    assert len(result.diff) == 1
    assert result.diff[0].removed == ()
    assert result.diff[0].added == (DB_ROUTE,)


def test_route_add_duplicate_fails(tmp_path: Path):
    src, root = _stage(tmp_path, REMOVED_ROUTE_PROPOSED)
    first, first_path = apply_candidate(
        _route_candidate(candidate_id="c-01"), proposed_dir=src, ephemeral_root=root
    )
    assert first.applied is True
    assert first_path is not None
    other_root = tmp_path / "other-runs"
    other_root.mkdir()
    # first_path is a complete snapshot dir: adding the same route again fails.
    result, path = apply_candidate(
        _route_candidate(candidate_id="c-02"), proposed_dir=first_path,
        ephemeral_root=other_root,
    )
    assert result.applied is False
    assert path is None
    assert any("already exists" in reason for reason in result.reasons)


def test_route_remove_success_and_edge_cases(tmp_path: Path):
    base_text = (REPO_ROOT / "lab/baseline/configs/r1.cfg").read_text()
    assert f"\n{DB_ROUTE}\n" in base_text
    src = _write_snapshot(tmp_path, "proposed", {"configs/r1.cfg": base_text})
    root = tmp_path / "runs"
    root.mkdir()

    result, path = apply_candidate(
        _route_candidate(candidate_id="c-01", remove=True),
        proposed_dir=src, ephemeral_root=root,
    )
    assert result.applied is True
    assert path is not None
    assert DB_ROUTE not in (path / "configs" / "r1.cfg").read_text().splitlines()
    assert result.diff[0].removed == (DB_ROUTE,)
    assert result.diff[0].added == ()

    # Zero matches fail.
    missing, _ = apply_candidate(
        _route_candidate(candidate_id="c-02", prefix="10.9.9.0/24", remove=True),
        proposed_dir=src, ephemeral_root=root,
    )
    assert missing.applied is False
    assert any("none" in reason for reason in missing.reasons)

    # Duplicated route lines fail (ambiguous removal).
    dup_text = base_text + f"{DB_ROUTE}\n"
    dup_src = _write_snapshot(tmp_path, "dup", {"configs/r1.cfg": dup_text})
    dup, _ = apply_candidate(
        _route_candidate(candidate_id="c-03", remove=True),
        proposed_dir=dup_src, ephemeral_root=root,
    )
    assert dup.applied is False
    assert any("multiple" in reason for reason in dup.reasons)


def test_host_bits_route_line_matches_canonical_network(tmp_path: Path):
    base_text = (REPO_ROOT / "lab/baseline/configs/r1.cfg").read_text()
    hostbits = base_text.replace(
        "ip route 198.51.100.0 255.255.255.0 10.0.12.2",
        "ip route 198.51.100.1 255.255.255.0 10.0.12.2",
        1,
    )
    src = _write_snapshot(tmp_path, "proposed", {"configs/r1.cfg": hostbits})
    root = tmp_path / "runs"
    root.mkdir()

    dup, _ = apply_candidate(
        _route_candidate(candidate_id="c-01"), proposed_dir=src, ephemeral_root=root
    )
    assert dup.applied is False
    assert any("already exists" in reason for reason in dup.reasons)

    removed, removed_path = apply_candidate(
        _route_candidate(candidate_id="c-02", remove=True),
        proposed_dir=src, ephemeral_root=root,
    )
    assert removed.applied is True
    assert removed_path is not None
    assert "198.51.100.1" not in (removed_path / "configs" / "r1.cfg").read_text()


def test_numeric_and_noncontiguous_masks_rejected(tmp_path: Path):
    root = tmp_path / "runs"
    root.mkdir()
    for index, bad_line in enumerate(
        (
            "ip route 10.9.0.0 24 10.0.12.2",
            "ip route 10.9.0.0 255.0.255.0 10.0.12.1",
        )
    ):
        r1 = f"hostname r1\n!\n{bad_line}\nend\n"
        src = _write_snapshot(tmp_path, f"proposed-{index}", {"configs/r1.cfg": r1})
        result, path = apply_candidate(
            _route_candidate(candidate_id=f"c-0{index + 1}", prefix="10.8.0.0/24"),
            proposed_dir=src, ephemeral_root=root,
        )
        assert result.applied is False, bad_line
        assert path is None
        assert any("unsupported route line" in reason for reason in result.reasons)


def test_unsupported_route_line_anywhere_rejects(tmp_path: Path):
    base_text = (REPO_ROOT / "lab/baseline/configs/r1.cfg").read_text()
    tainted = base_text.replace(
        DB_ROUTE, "ip route 10.0.0.0 255.0.0.0 10.0.12.2 name FOO", 1
    )
    src = _write_snapshot(tmp_path, "proposed", {"configs/r1.cfg": tainted})
    root = tmp_path / "runs"
    root.mkdir()
    # The op targets an unrelated prefix: the scan-everything rule still fires.
    result, path = apply_candidate(
        _route_candidate(prefix="10.9.9.0/24"), proposed_dir=src, ephemeral_root=root
    )
    assert result.applied is False
    assert path is None
    assert any("unsupported route line" in reason for reason in result.reasons)


def test_candidate_b_starts_from_pristine_source(tmp_path: Path):
    src, root = _stage(tmp_path, ACL_PROPOSED)
    result_a, path_a = apply_candidate(
        _acl_repair_candidate(candidate_id="c-01"),
        proposed_dir=src, ephemeral_root=root,
    )
    assert result_a.applied is True
    assert path_a is not None
    new_route = _route_candidate(candidate_id="c-02", prefix="10.9.0.0/24")
    result_b, path_b = apply_candidate(
        new_route, proposed_dir=src, ephemeral_root=root
    )
    assert result_b.applied is True
    assert path_b is not None
    assert path_b != path_a
    text_b = (path_b / "configs" / "r1.cfg").read_text()
    # B started from the pristine source: A's permit is absent, the deny stands.
    assert f" {DENY_10}\n" in text_b
    assert PERMIT_10 not in text_b.splitlines()
    assert "ip route 10.9.0.0 255.255.255.0 10.0.12.2" in text_b.splitlines()
    text_a = (path_a / "configs" / "r1.cfg").read_text()
    assert f" {PERMIT_10}\n" in text_a
    assert "10.9.0.0" not in text_a


def test_candidate_copy_matches_source_before_any_operation(tmp_path: Path):
    src, root = _stage(tmp_path, ACL_PROPOSED)
    result_a, _ = apply_candidate(
        _acl_repair_candidate(candidate_id="c-01"),
        proposed_dir=src, ephemeral_root=root,
    )
    assert result_a.applied is True
    copied_b = _create_candidate_copy(src, root, "c-02")
    try:
        assert _hash_tree(copied_b) == _hash_tree(src)
    finally:
        shutil.rmtree(copied_b, ignore_errors=True)
    result_b, path_b = apply_candidate(
        _route_candidate(candidate_id="c-02", prefix="10.9.0.0/24"),
        proposed_dir=src, ephemeral_root=root,
    )
    assert result_b.applied is True
    assert path_b is not None
    text_b = (path_b / "configs" / "r1.cfg").read_text()
    assert f" {DENY_10}\n" in text_b
    assert PERMIT_10 not in text_b.splitlines()


def test_original_sources_untouched(tmp_path: Path):
    watched = [ACL_PROPOSED, REMOVED_ROUTE_PROPOSED]
    before = {root: _hash_tree(root) for root in watched}
    acl_src = _snapshot_copy(ACL_PROPOSED, tmp_path / "work1")
    route_src = _snapshot_copy(REMOVED_ROUTE_PROPOSED, tmp_path / "work2")
    runs1 = tmp_path / "runs1"
    runs2 = tmp_path / "runs2"
    runs1.mkdir()
    runs2.mkdir()
    ok_acl, _ = apply_candidate(
        _acl_repair_candidate(), proposed_dir=acl_src, ephemeral_root=runs1
    )
    ok_route, _ = apply_candidate(
        _route_candidate(), proposed_dir=route_src, ephemeral_root=runs2
    )
    assert ok_acl.applied is True
    assert ok_route.applied is True
    apply_candidate(
        _acl_repair_candidate(candidate_id="c-09", seq=99),
        proposed_dir=acl_src, ephemeral_root=runs1,
    )
    apply_candidate(
        _acl_repair_candidate(candidate_id="c-10", node="../r1"),
        proposed_dir=acl_src, ephemeral_root=runs1,
    )
    after = {root: _hash_tree(root) for root in watched}
    assert before == after


def test_traversal_candidates_rejected_without_writing(tmp_path: Path):
    src, root = _stage(tmp_path, ACL_PROPOSED)
    evil = _acl_repair_candidate(candidate_id="c-01", node="../r1")
    result, path = apply_candidate(evil, proposed_dir=src, ephemeral_root=root)
    assert result.applied is False
    assert path is None
    assert not (root / "candidate-c-01").exists()

    nested = _acl_repair_candidate(candidate_id="c-02", node="sub/dir")
    result, path = apply_candidate(nested, proposed_dir=src, ephemeral_root=root)
    assert result.applied is False
    assert path is None
    assert not (root / "candidate-c-02").exists()

    marker = root / "not-a-dir"
    marker.write_text("x")
    result, path = apply_candidate(
        _acl_repair_candidate(candidate_id="c-03"), proposed_dir=src, ephemeral_root=marker
    )
    assert result.applied is False
    assert path is None


def test_overlapping_root_and_proposed_rejected(tmp_path: Path):
    src = _snapshot_copy(ACL_PROPOSED, tmp_path)
    before = _hash_tree(src)
    # Ephemeral root inside the proposed tree.
    inner, _ = apply_candidate(
        _acl_repair_candidate(), proposed_dir=src, ephemeral_root=src / "configs"
    )
    assert inner.applied is False
    assert any("overlap" in reason for reason in inner.reasons)
    # Identical directories.
    same, _ = apply_candidate(
        _acl_repair_candidate(), proposed_dir=src, ephemeral_root=src
    )
    assert same.applied is False
    # Proposed tree inside the ephemeral root.
    outer, _ = apply_candidate(
        _acl_repair_candidate(), proposed_dir=src, ephemeral_root=tmp_path
    )
    assert outer.applied is False
    assert _hash_tree(src) == before
    assert not (src / "configs" / "candidate-c-01").exists()
    assert not (tmp_path / "candidate-c-01").exists()


def test_path_failures_scrub_absolute_paths(tmp_path: Path):
    src, root = _stage(tmp_path, ACL_PROPOSED)
    marker = root / "not-a-dir"
    marker.write_text("x")
    result, _ = apply_candidate(
        _acl_repair_candidate(), proposed_dir=src, ephemeral_root=marker
    )
    assert result.applied is False
    assert str(tmp_path) not in result.model_dump_json()
    missing = root / "nope"
    result2, _ = apply_candidate(
        _acl_repair_candidate(), proposed_dir=missing, ephemeral_root=root
    )
    assert result2.applied is False
    assert "proposed directory not found" in result2.reasons
    assert str(tmp_path) not in result2.model_dump_json()


def test_symlinked_config_applies_on_copy_only(tmp_path: Path):
    outside = tmp_path / "outside.cfg"
    outside.write_text((ACL_PROPOSED / "configs" / "r1.cfg").read_text())
    snap = tmp_path / "proposed" / "configs"
    snap.mkdir(parents=True)
    (snap / "r1.cfg").symlink_to(outside)
    (snap / "r2.cfg").write_text("hostname r2\n!\nend\n")
    root = tmp_path / "runs"
    root.mkdir()
    before = outside.read_bytes()
    result, path = apply_candidate(
        _acl_repair_candidate(),
        proposed_dir=tmp_path / "proposed", ephemeral_root=root,
    )
    assert result.applied is True
    assert path is not None
    assert outside.read_bytes() == before
    copied = path / "configs" / "r1.cfg"
    assert copied.is_file()
    assert not copied.is_symlink()
    assert f" {PERMIT_10}" in copied.read_text().splitlines()


def test_keep_failed_dirs_leaves_copy_but_no_path(tmp_path: Path):
    src, root = _stage(tmp_path, ACL_PROPOSED)
    source_text = (src / "configs" / "r1.cfg").read_text()
    result, path = apply_candidate(
        _acl_repair_candidate(seq=99), proposed_dir=src, ephemeral_root=root,
        keep_failed_dirs=True,
    )
    assert result.applied is False
    assert path is None
    leftover = root / "candidate-c-01"
    assert leftover.is_dir()
    assert (leftover / "configs" / "r1.cfg").read_text() == source_text


def test_partial_copytree_failure_cleans_up_only_own_dir(tmp_path: Path, monkeypatch):
    import netops_lens.patch as patch_module

    src, root = _stage(tmp_path, ACL_PROPOSED)
    real_copytree = shutil.copytree

    def flaky_copytree(s, d, *args, **kwargs):
        real_copytree(s, d, *args, **kwargs)
        (Path(d) / "configs" / "partial.cfg").write_text("half written\n")
        raise OSError("disk on fire")

    monkeypatch.setattr(patch_module.shutil, "copytree", flaky_copytree)
    result, path = apply_candidate(
        _acl_repair_candidate(candidate_id="c-01"), proposed_dir=src, ephemeral_root=root
    )
    assert result.applied is False
    assert path is None
    assert any("cannot copy proposed snapshot" in reason for reason in result.reasons)
    # The partial directory created by this attempt is gone.
    assert not (root / "candidate-c-01").exists()
    # A retry with the same candidate ID can start cleanly.
    monkeypatch.undo()
    retry, retry_path = apply_candidate(
        _acl_repair_candidate(candidate_id="c-01"), proposed_dir=src, ephemeral_root=root
    )
    assert retry.applied is True
    assert retry_path is not None and retry_path.is_dir()


def test_preexisting_candidate_directory_is_never_removed(tmp_path: Path):
    src, root = _stage(tmp_path, ACL_PROPOSED)
    squatter = root / "candidate-c-07"
    squatter.mkdir()
    sentinel = squatter / "sentinel.txt"
    sentinel.write_text("do not touch\n")
    result, path = apply_candidate(
        _acl_repair_candidate(candidate_id="c-07"), proposed_dir=src, ephemeral_root=root
    )
    assert result.applied is False
    assert path is None
    assert any("already exists" in reason for reason in result.reasons)
    assert sentinel.read_text() == "do not touch\n"
