"""Configuration loading guarantees (no key required, no secrets exposed)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from netops_lens.config import (
    META_API_BASE_DEFAULT,
    META_MODEL_DEFAULT,
    auth_headers,
    chat_completions_url,
    load_settings,
)

CONFIG_VARS = [
    "META_API_KEY",
    "META_API_BASE",
    "META_MODEL",
    "BATFISH_HOST",
    "BATFISH_NETWORK",
    "AGENT_MAX_TOOL_CALLS",
    "MAX_CANDIDATES",
    "MAX_PATCH_RETRIES",
    "CANDIDATE_SUBMISSION_VARIANT",
]


@pytest.fixture
def clean_env(monkeypatch):
    for var in CONFIG_VARS:
        monkeypatch.delenv(var, raising=False)


def test_defaults_without_any_env(clean_env):
    settings = load_settings()
    assert settings.meta_api_key is None
    assert settings.meta_api_base == META_API_BASE_DEFAULT
    assert settings.meta_model == META_MODEL_DEFAULT
    assert settings.batfish_host == "localhost"
    assert settings.batfish_network == "netops-lens-lab"
    assert settings.agent_max_tool_calls == 8
    assert settings.max_candidates == 3
    assert settings.max_patch_retries == 1
    assert settings.candidate_submission_variant == "tool"
    assert chat_completions_url(settings) == META_API_BASE_DEFAULT + "/chat/completions"


def test_blank_strings_fall_back_to_defaults(clean_env, monkeypatch):
    monkeypatch.setenv("META_API_BASE", "")
    monkeypatch.setenv("META_MODEL", "   ")
    monkeypatch.setenv("BATFISH_HOST", "")
    monkeypatch.setenv("AGENT_MAX_TOOL_CALLS", "")
    monkeypatch.setenv("CANDIDATE_SUBMISSION_VARIANT", "")
    settings = load_settings()
    assert settings.meta_api_base == META_API_BASE_DEFAULT
    assert settings.meta_model == META_MODEL_DEFAULT
    assert settings.batfish_host == "localhost"
    assert settings.agent_max_tool_calls == 8
    assert settings.candidate_submission_variant == "tool"


def test_invalid_submission_variant_fails(clean_env, monkeypatch):
    monkeypatch.setenv("CANDIDATE_SUBMISSION_VARIANT", "carrier-pigeon")
    with pytest.raises(RuntimeError, match="invalid_config"):
        load_settings()


def test_invalid_numeric_values_fail(clean_env, monkeypatch):
    monkeypatch.setenv("AGENT_MAX_TOOL_CALLS", "many")
    with pytest.raises(RuntimeError, match="invalid_config"):
        load_settings()
    monkeypatch.setenv("AGENT_MAX_TOOL_CALLS", "8")
    monkeypatch.setenv("MAX_CANDIDATES", "0")
    with pytest.raises(RuntimeError, match="invalid_config"):
        load_settings()


def test_api_key_optional_and_never_exposed(clean_env, monkeypatch):
    assert load_settings().meta_api_key is None
    monkeypatch.setenv("META_API_KEY", "   ")
    assert load_settings().meta_api_key is None
    with pytest.raises(RuntimeError, match="missing_api_key"):
        auth_headers(load_settings())
    monkeypatch.setenv("META_API_KEY", "test-key-value")
    settings = load_settings()
    assert settings.meta_api_key is not None
    assert "test-key-value" not in repr(settings)
    headers = auth_headers(settings)
    assert headers["Authorization"] == "Bearer test-key-value"


def test_env_file_loading_is_contained(clean_env, tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("BATFISH_HOST=custom-batfish\n")
    before = set(os.environ)
    try:
        assert load_settings(env_file=env_file).batfish_host == "custom-batfish"
    finally:
        for key in set(os.environ) - before:
            del os.environ[key]
    assert load_settings().batfish_host == "localhost"


def test_env_example_documents_configurable_vars():
    content = (Path(__file__).resolve().parent.parent / ".env.example").read_text()
    for var in ("META_API_BASE", "META_MODEL", "CANDIDATE_SUBMISSION_VARIANT"):
        assert var in content
