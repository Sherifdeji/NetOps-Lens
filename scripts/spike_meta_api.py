"""Phase 0 Meta Model API smoke test (read-only, no secrets logged).

Verifies, in order:
  (a) authenticated chat completion against the configured Muse Spark model;
  (b) a complete dummy ``echo`` tool-calling round trip;
  (c) acceptance of the real nested ``submit_candidate_patch`` tool schema,
      or the validated structured-output fallback.

Exit 0 with PASS lines on success. Any failure prints exactly one FAIL line
carrying the failure category (never the API key or response secrets) and
exits non-zero:
  missing_api_key | network_error | auth_error | model_error |
  tool_call_failed | tool_schema_rejected | unexpected_response
"""

from __future__ import annotations

import json
import sys

import httpx

from netops_lens.config import auth_headers, chat_completions_url, load_settings
from netops_lens.models import CandidateSubmission

TIMEOUT_S = 60.0

ECHO_TOOL = {
    "type": "function",
    "function": {
        "name": "echo",
        "description": "Repeat the supplied text back verbatim (smoke test).",
        "parameters": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
            "additionalProperties": False,
        },
    },
}


def fail(category: str, detail: str = "") -> int:
    suffix = f": {detail}" if detail else ""
    print(f"FAIL {category}{suffix}", flush=True)
    return 1


def post(client: httpx.Client, url: str, headers: dict, payload: dict) -> httpx.Response:
    try:
        return client.post(url, headers=headers, json=payload)
    except httpx.ConnectError as exc:
        raise RuntimeError(f"network_error: cannot reach {url}") from exc
    except httpx.TimeoutException as exc:
        raise RuntimeError("network_error: request timed out") from exc
    except httpx.HTTPError as exc:
        raise RuntimeError(f"network_error: {type(exc).__name__}") from exc


def check_chat_completion(client: httpx.Client, url: str, headers: dict, model: str) -> bool:
    """Step (a): one authenticated completion; assert the model responds."""
    try:
        resp = post(
            client,
            url,
            headers,
            {
                "model": model,
                "messages": [{"role": "user", "content": "Reply with exactly: smoke-ok"}],
            },
        )
    except RuntimeError as exc:
        print(f"FAIL {exc}", flush=True)
        return False
    if resp.status_code in (401, 403):
        print("FAIL auth_error", flush=True)
        return False
    if resp.status_code == 404:
        print("FAIL model_error: chat-completions endpoint or model not found", flush=True)
        return False
    if resp.status_code != 200:
        print(f"FAIL unexpected_response: http_{resp.status_code}", flush=True)
        return False
    try:
        body = resp.json()
        content = body["choices"][0]["message"]["content"]
    except ValueError, KeyError, IndexError, TypeError:
        print("FAIL unexpected_response: malformed chat-completion body", flush=True)
        return False
    if not isinstance(content, str) or not content.strip():
        print("FAIL unexpected_response: empty completion content", flush=True)
        return False
    observed_model = body.get("model", "?")
    print(f"PASS chat_completion model={observed_model} content={content.strip()!r}")
    print(f"OBSERVED completion_keys={sorted(body.keys())}")
    return True


def check_echo_round_trip(client: httpx.Client, url: str, headers: dict, model: str) -> bool:
    """Step (b): model emits a structured echo call; we run it; it acks."""
    messages = [
        {
            "role": "user",
            "content": "Call the echo tool exactly once with text 'ping-smoke'.",
        }
    ]
    try:
        resp = post(
            client,
            url,
            headers,
            {"model": model, "messages": messages, "tools": [ECHO_TOOL]},
        )
    except RuntimeError as exc:
        print(f"FAIL {exc}", flush=True)
        return False
    if resp.status_code != 200:
        print(f"FAIL tool_call_failed: http_{resp.status_code}", flush=True)
        return False
    try:
        body = resp.json()
        assistant_msg = body["choices"][0]["message"]
        call = assistant_msg["tool_calls"][0]
        assert call["type"] == "function"
        assert call["function"]["name"] == "echo"
        args = json.loads(call["function"]["arguments"])
        assert args == {"text": "ping-smoke"}
        call_id = call["id"]
    except ValueError, KeyError, IndexError, TypeError, AssertionError:
        print("FAIL tool_call_failed: no well-formed echo tool call", flush=True)
        return False
    print(f"OBSERVED tool_call_shape={sorted(call.keys())} args={args}")
    tool_result = {"echoed": args["text"]}
    follow_up = [
        *messages,
        {"role": "assistant", "tool_calls": assistant_msg["tool_calls"]},
        {"role": "tool", "tool_call_id": call_id, "content": json.dumps(tool_result)},
    ]
    try:
        resp2 = post(client, url, headers, {"model": model, "messages": follow_up})
    except RuntimeError as exc:
        print(f"FAIL {exc}", flush=True)
        return False
    if resp2.status_code != 200:
        print(f"FAIL tool_call_failed: http_{resp2.status_code} on result return", flush=True)
        return False
    try:
        ack = resp2.json()["choices"][0]["message"]["content"]
    except ValueError, KeyError, IndexError, TypeError:
        print("FAIL tool_call_failed: malformed acknowledgement body", flush=True)
        return False
    if not isinstance(ack, str) or not ack.strip():
        print("FAIL tool_call_failed: empty acknowledgement", flush=True)
        return False
    print(f"PASS echo_round_trip ack={ack.strip()!r}")
    return True


def check_nested_schema(client: httpx.Client, url: str, headers: dict, model: str) -> str | None:
    """Step (c): nested CandidatePatch schema as a tool, else fallback."""
    schema = CandidateSubmission.model_json_schema()
    nested_tool = {
        "type": "function",
        "function": {
            "name": "submit_candidate_patch",
            "description": "Submit one structured candidate patch (smoke test).",
            "parameters": schema,
        },
    }
    try:
        resp = post(
            client,
            url,
            headers,
            {
                "model": model,
                "messages": [{"role": "user", "content": "No fix needed; reply briefly."}],
                "tools": [ECHO_TOOL, nested_tool],
            },
        )
    except RuntimeError as exc:
        print(f"FAIL {exc}", flush=True)
        return None
    if resp.status_code == 200:
        print("PASS nested_schema_accepted variant=tool")
        return "tool"
    print(f"OBSERVED nested_schema_status=http_{resp.status_code}; trying fallback")
    fallback_payload = {
        "model": model,
        "messages": [{"role": "user", "content": "No fix needed; reply briefly."}],
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "candidate_patch",
                "schema": schema,
                "strict": True,
            },
        },
    }
    try:
        resp2 = post(client, url, headers, fallback_payload)
    except RuntimeError as exc:
        print(f"FAIL {exc}", flush=True)
        return None
    if resp2.status_code == 200:
        print("PASS structured_output_accepted variant=structured_output")
        return "structured_output"
    print(
        f"FAIL tool_schema_rejected: tool_http={resp.status_code} "
        f"fallback_http={resp2.status_code}",
        flush=True,
    )
    return None


def main() -> int:
    try:
        settings = load_settings()
    except RuntimeError as exc:
        return fail(str(exc).split(":")[0], "check .env configuration")
    if settings.meta_api_key is None:
        return fail("missing_api_key", "set META_API_KEY in .env (Phase 3 blocker)")
    url = chat_completions_url(settings)
    headers = auth_headers(settings)
    print(f"OBSERVED endpoint={url} model={settings.meta_model}")
    with httpx.Client(timeout=TIMEOUT_S) as client:
        if not check_chat_completion(client, url, headers, settings.meta_model):
            return 1
        if not check_echo_round_trip(client, url, headers, settings.meta_model):
            return 1
        variant = check_nested_schema(client, url, headers, settings.meta_model)
    if variant is None:
        return 1
    print(f"LIVE_SUBMISSION_VARIANT={variant}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
