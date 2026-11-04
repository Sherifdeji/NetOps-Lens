"""Batfish session lifecycle and answer conversion.

This is the ONLY module that imports Pybatfish. No pandas DataFrame and no
Pybatfish object crosses this module's boundary: answers leave as plain
JSON-serializable record dicts. All failures surface as ``BatfishError`` so
callers (Phase 2 ``tools.py``) can convert them to typed tool results.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pandas as pd
from pybatfish.client.session import Session
from pybatfish.datamodel import HeaderConstraints, PathConstraints

RecordValue = str | int | float | bool | None
Record = dict[str, RecordValue]


class BatfishError(Exception):
    """Anything that prevents a trustworthy Batfish answer."""


def _convert(value: object) -> object:
    """Convert one answer cell to a JSON-serializable value."""
    if value is None:
        return None
    if isinstance(value, bool | int | float | str):
        if isinstance(value, float) and pd.isna(value):
            return None
        return value
    to_dict = getattr(value, "dict", None)
    if callable(to_dict):
        return _convert(to_dict())
    if isinstance(value, dict):
        return {str(k): _convert(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_convert(v) for v in value]
    item = getattr(value, "item", None)
    if callable(item):
        return _convert(item())
    if pd.isna(value):  # NaT and other scalar missing markers
        return None
    raise BatfishError(f"unconvertible answer cell of type {type(value).__name__}")


def to_records(frame: pd.DataFrame, *, question: str) -> list[Record]:
    """Convert an answer frame to JSON-serializable records (no DataFrame escapes)."""
    try:
        raw_rows = frame.to_dict(orient="records")
    except Exception as exc:
        raise BatfishError(f"question {question!r}: cannot read answer frame") from exc
    records: list[Record] = []
    for row in raw_rows:
        try:
            converted = {str(k): _convert(v) for k, v in row.items()}
            json.dumps(converted)
        except (BatfishError, TypeError, ValueError) as exc:
            raise BatfishError(f"question {question!r}: answer not JSON-serializable") from exc
        records.append(cast(Record, converted))
    return records


@dataclass(frozen=True)
class HealthRecords:
    """Raw health inputs for one snapshot (verdict logic lives in Phase 2)."""

    parse_status: tuple[Record, ...] = ()
    init_issues: tuple[Record, ...] = ()
    nodes: tuple[Record, ...] = ()


_CANDIDATE_ID_PATTERN = re.compile(r"c-[0-9]+")
_GENERATED_SNAPSHOT_PATTERN = re.compile(r"[a-z0-9-]+-candidate-c-[0-9]+")


def _is_generated_candidate_name(name: str) -> bool:
    """Full-shape check for a generated candidate snapshot name.

    Mirrors the ``candidate_snapshot_name`` output shape: a sanitized tag
    (lowercase alphanumeric-plus-dash), ``-candidate-``, and a ``c-<digits>``
    ID. Baseline, proposed, foreign, and traversal strings never match.
    """
    return _GENERATED_SNAPSHOT_PATTERN.fullmatch(name) is not None


def is_candidate_snapshot_name(name: str) -> bool:
    """Public form of the generated-name check for cross-module guards."""
    return _is_generated_candidate_name(name)


def candidate_snapshot_name(tag: str, candidate_id: str) -> str:
    """Build a ``{tag}-candidate-{candidate_id}`` snapshot name.

    The tag is sanitized with the same lowercase alphanumeric-plus-dash
    rule as ``cli.run_network_name``; the candidate ID must match the
    Python ``c-NN`` contract. Anything else is a ``BatfishError``.
    """
    safe_tag = "".join(c if c.isalnum() else "-" for c in tag.lower())
    if not safe_tag:
        raise BatfishError(f"invalid snapshot tag: {tag!r}")
    if _CANDIDATE_ID_PATTERN.fullmatch(candidate_id) is None:
        raise BatfishError(f"invalid candidate id: {candidate_id!r}")
    return f"{safe_tag}-candidate-{candidate_id}"


def _is_missing_snapshot(exc: Exception) -> bool:
    """Detect a missing-snapshot (404) outcome without importing requests."""
    response = getattr(exc, "response", None)
    return getattr(response, "status_code", None) == 404


class BatfishClient:
    """Owns one Batfish session: connect, init snapshots, ask questions."""

    @staticmethod
    def flow_headers(
        *,
        src_ip: str,
        dst_ip: str,
        protocol: str,
        dst_port: int | None = None,
    ) -> HeaderConstraints:
        """Build Batfish header constraints for one declared flow.

        Returns an opaque Pybatfish object: callers pass it straight to
        :meth:`ask` without importing Pybatfish themselves.
        """
        kwargs: dict[str, object] = {
            "srcIps": src_ip,
            "dstIps": dst_ip,
            "ipProtocols": [protocol],
        }
        if dst_port is not None:
            kwargs["dstPorts"] = [dst_port]
        return HeaderConstraints(**kwargs)  # type: ignore[arg-type]

    @staticmethod
    def start_path(start_location: str) -> PathConstraints:
        """Build Batfish path constraints for one start location (opaque)."""
        return PathConstraints(startLocation=start_location)

    def __init__(self, host: str, network: str) -> None:
        self._host = host
        self._network = network
        self._session: Session | None = None
        self._candidate_snapshots: set[str] = set()

    @property
    def host(self) -> str:
        return self._host

    @property
    def network(self) -> str:
        return self._network

    def connect(self) -> None:
        """Open the session and select the network (raises BatfishError)."""
        try:
            session = Session(host=self._host)
            session.set_network(self._network)
        except Exception as exc:
            raise BatfishError(
                f"cannot reach Batfish at {self._host!r}: {type(exc).__name__}"
            ) from exc
        self._session = session

    def _require_session(self) -> Session:
        if self._session is None:
            raise BatfishError("not connected: call connect() first")
        return self._session

    def delete_network(self) -> None:
        """Delete this client's Batfish network (cleanup after a run).

        N-03: works even when ``connect()`` failed partway — a transient
        session is opened so a partially created run network can still be
        removed. A refusal or failure surfaces as BatfishError; callers
        doing best-effort cleanup must catch it.
        """
        session = self._session
        if session is None:
            try:
                session = Session(host=self._host)
            except Exception as exc:
                raise BatfishError(
                    f"cannot reach Batfish at {self._host!r}: {type(exc).__name__}"
                ) from exc
        try:
            session.delete_network(self._network)
        except Exception as exc:
            raise BatfishError(f"cannot delete network {self._network!r}: {exc}") from exc

    def init_snapshot(self, path: str | Path, name: str, *, overwrite: bool = True) -> str:
        """Load a snapshot directory into Batfish; returns the snapshot name."""
        session = self._require_session()
        snapshot_dir = Path(path)
        if not snapshot_dir.is_dir():
            raise BatfishError(f"snapshot directory not found: {snapshot_dir}")
        try:
            session.init_snapshot(str(snapshot_dir), name=name, overwrite=overwrite)
        except Exception as exc:
            raise BatfishError(
                f"init_snapshot failed for {str(snapshot_dir)!r} as {name!r}: {type(exc).__name__}"
            ) from exc
        return name

    def register_candidate_snapshot(self, name: str) -> None:
        """Record a candidate snapshot this client created.

        Only generated candidate snapshot names validate: anything else —
        baseline, proposed, foreign, or traversal strings — raises
        ``BatfishError`` and registers nothing. Phase 4.2 calls this after
        a successful ``init_snapshot(..., overwrite=False)``.
        """
        if not _is_generated_candidate_name(name):
            raise BatfishError(f"refusing to register non-candidate snapshot {name!r}")
        self._candidate_snapshots.add(name)

    def is_registered_candidate(self, name: str) -> bool:
        """Whether this client registered ``name`` as its own candidate snapshot."""
        return name in self._candidate_snapshots

    def delete_snapshot(self, name: str) -> None:
        """Delete one candidate snapshot this run created.

        The generated-name shape is re-checked at delete time (defense in
        depth), so baseline and proposed snapshots are protected
        unconditionally, independently of registry state. Names never
        registered are refused without contacting Batfish. The name leaves
        the registry only on success or on an explicitly missing-snapshot
        (404) outcome; other failures keep the registration. Everything
        surfaces as ``BatfishError``; callers doing best-effort cleanup
        must catch it.
        """
        if not _is_generated_candidate_name(name):
            raise BatfishError(f"refusing to delete non-candidate snapshot {name!r}")
        if name not in self._candidate_snapshots:
            raise BatfishError(f"refusing to delete unregistered snapshot {name!r}")
        session = self._session
        if session is None:
            try:
                session = Session(host=self._host)
            except Exception as exc:
                raise BatfishError(
                    f"cannot reach Batfish at {self._host!r}: {type(exc).__name__}"
                ) from exc
        try:
            session.delete_snapshot(name)
        except Exception as exc:
            if _is_missing_snapshot(exc):
                self._candidate_snapshots.discard(name)
                raise BatfishError(f"snapshot {name!r} already absent") from exc
            raise BatfishError(f"cannot delete snapshot {name!r}: {exc}") from exc
        self._candidate_snapshots.discard(name)

    def ask(
        self,
        question: str,
        snapshot: str,
        reference_snapshot: str | None = None,
        **params: object,
    ) -> list[Record]:
        """Run one Batfish question against a snapshot; return plain records.

        ``reference_snapshot`` is routed to ``.answer()`` (used by
        differential questions); all other params go to the question call.
        """
        session = self._require_session()
        try:
            ask_question = getattr(session.q, question)
        except AttributeError as exc:
            raise BatfishError(f"unknown Batfish question: {question!r}") from exc
        try:
            if reference_snapshot is None:
                answer = ask_question(**params).answer(snapshot=snapshot)
            else:
                answer = ask_question(**params).answer(
                    snapshot=snapshot, reference_snapshot=reference_snapshot
                )
            frame = answer.frame()
        except Exception as exc:
            raise BatfishError(
                f"question {question!r} on snapshot {snapshot!r} failed: {type(exc).__name__}"
            ) from exc
        return to_records(frame, question=question)

    def health_records(self, snapshot: str) -> HealthRecords:
        """Fetch the three raw health inputs for one snapshot."""
        return HealthRecords(
            parse_status=tuple(self.ask("fileParseStatus", snapshot)),
            init_issues=tuple(self.ask("initIssues", snapshot)),
            nodes=tuple(self.ask("nodeProperties", snapshot)),
        )
