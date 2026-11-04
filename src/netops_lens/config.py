"""Environment loading and run limits for NetOps Lens.

The API key is read programmatically from the environment / `.env` and is
never printed, logged, or included in error output. It is stored as
``SecretStr`` so a settings object can never leak the key through ``repr``.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError

load_dotenv()

SubmissionVariant = Literal["tool", "structured_output"]

META_API_BASE_DEFAULT = "https://api.meta.ai/v1"
META_MODEL_DEFAULT = "muse-spark-1.3"


class Settings(BaseModel):
    """Run configuration. Missing keys fail loudly at the call site, not here.

    Environment variables (all optional except as noted)::

        META_API_KEY                 API key; absent/blank means no live API
                                     (imports and offline tests never require it)
        META_API_BASE                API base URL (default https://api.meta.ai/v1)
        META_MODEL                   chat model ID (default muse-spark-1.3)
        BATFISH_HOST                 Batfish host (default localhost)
        BATFISH_NETWORK              Batfish network (default netops-lens-lab)
        AGENT_MAX_TOOL_CALLS         investigation loop bound (default 8)
        MAX_CANDIDATES               candidates per run (default 3)
        MAX_PATCH_RETRIES            candidate retry rounds (default 1)
        CANDIDATE_SUBMISSION_VARIANT "tool" or "structured_output" (default tool)
        KEEP_CANDIDATE_DIRS "true"/"false" (default false)
    """

    model_config = ConfigDict(extra="forbid")

    meta_api_key: SecretStr | None = None
    meta_api_base: str = META_API_BASE_DEFAULT
    meta_model: str = META_MODEL_DEFAULT
    batfish_host: str = "localhost"
    batfish_network: str = "netops-lens-lab"
    agent_max_tool_calls: int = Field(default=8, ge=1)
    max_candidates: int = Field(default=3, ge=1)
    max_patch_retries: int = Field(default=1, ge=0)
    # Default "tool" is provisional until scripts/spike_meta_api.py confirms
    # the API accepts the nested submit_candidate_patch schema (Phase 0/3).
    candidate_submission_variant: SubmissionVariant = "tool"
    keep_candidate_dirs: bool = False


def _get_str(name: str, default: str) -> str:
    """String setting where blank (or whitespace-only) means 'use the default'."""
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip()


def _get_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw.strip())
    except ValueError as exc:
        raise RuntimeError(f"invalid_config: {name} must be an integer") from exc


def _get_bool(name: str, default: bool) -> bool:
    """Boolean setting; blank means the default, other non-bool text fails."""
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    lowered = raw.strip().lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    raise RuntimeError(f"invalid_config: {name} must be 'true' or 'false'")


def load_settings(env_file: str | os.PathLike[str] | None = None) -> Settings:
    """Load settings from the environment, optionally via an explicit file."""
    if env_file is not None:
        load_dotenv(dotenv_path=Path(env_file), override=True)
    raw_key = os.environ.get("META_API_KEY")
    variant_raw = _get_str("CANDIDATE_SUBMISSION_VARIANT", "tool")
    if variant_raw not in ("tool", "structured_output"):
        raise RuntimeError(
            "invalid_config: CANDIDATE_SUBMISSION_VARIANT must be 'tool' or 'structured_output'"
        )
    try:
        return Settings(
            meta_api_key=(SecretStr(raw_key.strip()) if raw_key and raw_key.strip() else None),
            meta_api_base=_get_str("META_API_BASE", META_API_BASE_DEFAULT),
            meta_model=_get_str("META_MODEL", META_MODEL_DEFAULT),
            batfish_host=_get_str("BATFISH_HOST", "localhost"),
            batfish_network=_get_str("BATFISH_NETWORK", "netops-lens-lab"),
            agent_max_tool_calls=_get_int("AGENT_MAX_TOOL_CALLS", 8),
            max_candidates=_get_int("MAX_CANDIDATES", 3),
            max_patch_retries=_get_int("MAX_PATCH_RETRIES", 1),
            candidate_submission_variant=variant_raw,  # type: ignore[arg-type]
            keep_candidate_dirs=_get_bool("KEEP_CANDIDATE_DIRS", False),
        )
    except ValidationError as exc:
        raise RuntimeError(f"invalid_config: {exc.errors()[0]['loc']}") from exc


def chat_completions_url(settings: Settings) -> str:
    """Full chat-completions endpoint URL for the configured API base."""
    return settings.meta_api_base.rstrip("/") + "/chat/completions"


def auth_headers(settings: Settings) -> dict[str, str]:
    """Bearer headers. Raises if no key is configured (never fabricates one)."""
    if settings.meta_api_key is None:
        raise RuntimeError("missing_api_key: set META_API_KEY in .env")
    return {
        "Authorization": f"Bearer {settings.meta_api_key.get_secret_value()}",
        "Content-Type": "application/json",
    }
