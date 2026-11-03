"""F-06 transport reliability tests: mocked httpx, exact production path.

Every case drives ``default_transport`` with an injected
``httpx.MockTransport`` client. Transport failures must surface as the
established typed ``AgentError`` (consumed by ``run_stage_b`` into a
failure narrative) and must never mutate or replace Stage A output.
Error messages carry only the failure category: planted secrets in mock
bodies must never appear in them.
"""

from __future__ import annotations

import json

import httpx
import pytest

from netops_lens.agent import AgentError, default_transport, run_stage_b
from netops_lens.config import Settings
from netops_lens.evidence import EvidenceStore
from tests.test_agent import _assessment, _intent, BASE, PROP
from tests._fakes import FakeClient

SECRET = "sk-live-SECRET-PLANTED"


def _settings() -> Settings:
    return Settings(
        meta_api_key="test-key",  # noqa: S106 - test fixture, not a secret
    )


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def _ok_message(**overrides) -> dict:
    """Mock a real Chat Completions choice: finish_reason is a sibling of
    message on choices[0], never nested inside the message (R-1)."""
    finish = overrides.pop("finish_reason", "stop")
    message = {"role": "assistant", "content": "hello"}
    message.update(overrides)
    return {"choices": [{"message": message, "finish_reason": finish}]}


def _transport(handler) -> tuple:
    seen: list[dict] = []

    def wrapped(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content.decode()))
        return handler(request)

    return default_transport(_settings(), _client(wrapped)), seen


def test_successful_completion():
    transport, seen = _transport(
        lambda request: httpx.Response(200, json=_ok_message(content="done"))
    )
    out = transport([{"role": "user", "content": "hi"}], [])
    assert out == {"content": "done", "tool_calls": []}
    assert seen[0]["model"] == "muse-spark-1.3"
    assert "tools" not in seen[0]


def test_tools_sent_and_multiple_calls_paired():
    body = _ok_message(
        content=None,
        finish_reason="tool_calls",
        tool_calls=[
            {
                "id": "call_a",
                "type": "function",
                "function": {"name": "trace_flow", "arguments": '{"flow_id": "f"}'},
            },
            {
                "id": "call_b",
                "type": "function",
                "function": {"name": "get_routes", "arguments": '{"node": "r1"}'},
            },
        ],
    )
    specs = [{"type": "function", "function": {"name": "trace_flow"}}]
    transport, seen = _transport(lambda request: httpx.Response(200, json=body))
    out = transport([{"role": "user", "content": "hi"}], specs)
    assert seen[0]["tools"] == specs
    assert [c["id"] for c in out["tool_calls"]] == ["call_a", "call_b"]
    assert [c["name"] for c in out["tool_calls"]] == ["trace_flow", "get_routes"]
    assert json.loads(out["tool_calls"][0]["arguments"]) == {"flow_id": "f"}


def test_auth_failure():
    for status in (401, 403):
        transport, _ = _transport(lambda request: httpx.Response(status, json={}))
        with pytest.raises(AgentError, match="auth_error"):
            transport([], [])


def test_http_5xx():
    transport, _ = _transport(
        lambda request: httpx.Response(500, json={"error": SECRET})
    )
    with pytest.raises(AgentError, match="unexpected_response http_500") as excinfo:
        transport([], [])
    assert SECRET not in str(excinfo.value)


def test_connection_timeout():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("too slow", request=request)

    transport, _ = _transport(handler)
    with pytest.raises(AgentError, match="timed out"):
        transport([], [])


def test_invalid_json_body():
    transport, _ = _transport(
        lambda request: httpx.Response(200, content=b"not json {{")
    )
    with pytest.raises(AgentError, match="malformed completion body"):
        transport([], [])


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"choices": []},
        {"choices": [{}]},
        {"choices": ["not-a-dict"]},
        {"choices": [{"message": None}]},
        {"choices": [{"message": "just a string"}]},
        {"choices": [{"finish_reason": "stop"}]},
    ],
)
def test_malformed_bodies(body):
    transport, _ = _transport(lambda request: httpx.Response(200, json=body))
    with pytest.raises(AgentError, match="malformed completion body"):
        transport([], [])


def test_finish_reason_read_from_choice_not_message():
    # R-1: a message-nested "stop" must not rescue a choice-level "length".
    body = _ok_message(content="partial...", finish_reason="length")
    body["choices"][0]["message"]["finish_reason"] = "stop"
    transport, _ = _transport(lambda request: httpx.Response(200, json=body))
    with pytest.raises(AgentError, match="incomplete response"):
        transport([], [])


def test_partial_content_with_length_is_never_accepted():
    # R-1: truncated content must never surface as a completed response.
    body = _ok_message(
        content="Here is the candidate you asked for",
        finish_reason="length",
    )
    transport, _ = _transport(lambda request: httpx.Response(200, json=body))
    with pytest.raises(AgentError, match=r"incomplete response.*length"):
        transport([], [])


@pytest.mark.parametrize(
    "tool_calls",
    [
        [{"id": "x", "type": "function"}],
        [{"type": "function", "function": {"name": "trace_flow"}}],
        [{"id": "x", "type": "function", "function": "not-a-dict"}],
        {"not": "a list"},
        [{"id": "x", "type": "function", "function": {"arguments": 42}}],
    ],
)
def test_malformed_tool_calls(tool_calls):
    body = _ok_message(finish_reason="tool_calls", tool_calls=tool_calls)
    transport, _ = _transport(lambda request: httpx.Response(200, json=body))
    with pytest.raises(AgentError, match="malformed tool call"):
        transport([], [])


@pytest.mark.parametrize("finish", ["length", "content_filter", "weird_halt"])
def test_truncated_or_unexpected_finish_is_incomplete(finish):
    body = _ok_message(content="partial...", finish_reason=finish)
    transport, _ = _transport(lambda request: httpx.Response(200, json=body))
    with pytest.raises(AgentError, match="incomplete response"):
        transport([], [])


def test_error_messages_hide_bodies_and_credentials():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, content=SECRET.encode())

    transport, _ = _transport(handler)
    with pytest.raises(AgentError) as excinfo:
        transport([], [])
    assert SECRET not in str(excinfo.value)
    assert "Authorization" not in str(excinfo.value)


def test_truncated_tool_calls_never_become_submissions():
    # R-1: a length-truncated response carrying tool calls must fail the
    # run instead of executing anything it contains.
    body = {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "partial",
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {
                                "name": "submit_candidate_patch",
                                "arguments": "{}",
                            },
                        }
                    ],
                },
                "finish_reason": "length",
            }
        ]
    }
    args = {"rationale": "x", "operations": [], "target_flow_ids": []}
    body["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"] = json.dumps(args)
    before = _assessment().model_dump_json()
    assessment = _assessment()
    store = EvidenceStore()
    result = run_stage_b(
        FakeClient(),
        store,
        assessment,
        _intent(),
        BASE,
        PROP,
        settings=_settings(),
        transport=default_transport(
            _settings(), _client(lambda request: httpx.Response(200, json=body))
        ),
    )
    assert result.narrative is not None and "transport_error" in result.narrative
    assert "incomplete response" in result.narrative
    assert result.candidates == []
    assert result.tool_activity == []
    assert assessment.model_dump_json() == before


def test_transport_failure_becomes_stage_b_failure_narrative():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    before = _assessment().model_dump_json()
    assessment = _assessment()
    store = EvidenceStore()
    result = run_stage_b(
        FakeClient(),
        store,
        assessment,
        _intent(),
        BASE,
        PROP,
        settings=_settings(),
        transport=default_transport(_settings(), _client(handler)),
    )
    assert result.narrative is not None and result.narrative.startswith("Stage B failed: ")
    assert "transport_error" in result.narrative
    assert SECRET not in result.narrative
    assert result.candidates == []
    assert assessment.model_dump_json() == before
