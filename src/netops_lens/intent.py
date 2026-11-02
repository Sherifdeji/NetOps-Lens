"""Intent file loading (YAML -> validated Intent). No Batfish, no LLM."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from netops_lens.models import FlowSpec, Intent

_FLOW_KEYS = {"id", "src", "dst", "protocol", "dst_port", "start_location"}


class IntentError(Exception):
    """A malformed or invalid intent file."""


def _flow_from_mapping(mapping: object, *, clause: str, index: int) -> FlowSpec:
    where = f"{clause}[{index}]"
    if not isinstance(mapping, dict):
        raise IntentError(f"{where}: flow entry must be a mapping")
    unknown = set(mapping) - _FLOW_KEYS
    if unknown:
        raise IntentError(f"{where}: unknown keys {sorted(unknown)}")
    for key in ("id", "src", "dst", "protocol", "start_location"):
        if key not in mapping:
            raise IntentError(f"{where}: missing required key {key!r}")
    try:
        return FlowSpec(
            flow_id=mapping["id"],
            src_ip=mapping["src"],
            dst_ip=mapping["dst"],
            protocol=mapping["protocol"],
            dst_port=mapping.get("dst_port"),
            start_location=mapping["start_location"],
        )
    except ValidationError as exc:
        raise IntentError(f"{where}: {exc.errors()[0]['msg']}") from exc


def load_intent(path: str | Path) -> Intent:
    """Load and validate an intent.yaml file."""
    intent_path = Path(path)
    if not intent_path.is_file():
        raise IntentError(f"intent file not found: {intent_path}")
    try:
        raw = yaml.safe_load(intent_path.read_text())
    except yaml.YAMLError as exc:
        raise IntentError(f"malformed YAML in {intent_path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise IntentError(f"{intent_path}: top level must be a mapping")
    if "version" not in raw:
        raise IntentError(f"{intent_path}: missing required key 'version'")
    clauses: dict[str, list[FlowSpec]] = {}
    for clause in ("must_reach", "must_not_reach"):
        entries = raw.get(clause, [])
        if not isinstance(entries, list):
            raise IntentError(f"{intent_path}: {clause!r} must be a list")
        clauses[clause] = [
            _flow_from_mapping(entry, clause=clause, index=i) for i, entry in enumerate(entries)
        ]
    try:
        return Intent(
            version=raw["version"],
            description=raw.get("description", ""),
            must_reach=clauses["must_reach"],
            must_not_reach=clauses["must_not_reach"],
        )
    except ValidationError as exc:
        raise IntentError(f"{intent_path}: {exc.errors()[0]['msg']}") from exc
