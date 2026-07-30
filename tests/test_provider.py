"""Tests for agent.llm.provider — provider-agnostic LLM wrapper.

LiteLLM is NOT required for these tests: LiteLLMProvider takes an injectable
`completion_fn` (defaults to litellm.completion when installed). Tests inject a fake
returning OpenAI-shaped responses to assert the *normalization* logic.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent.llm.provider import LiteLLMProvider, LLMResponse  # noqa: E402


def _msg(content=None, tool_calls=None):
    """Build an OpenAI-shaped assistant message."""
    tc = None
    if tool_calls is not None:
        tc = [
            SimpleNamespace(
                id=f"call_{i}",
                type="function",
                function=SimpleNamespace(
                    name=t["name"],
                    arguments=t.get("arguments", "{}"),
                ),
            )
            for i, t in enumerate(tool_calls)
        ]
    return SimpleNamespace(content=content, tool_calls=tc)


def _resp(message):
    return {"choices": [SimpleNamespace(message=message, finish_reason="stop")]}


def fake_completion(response):
    def _fn(model, messages, tools=None, **kw):
        _fn.last_model = model
        _fn.last_messages = messages
        _fn.last_tools = tools
        _fn.last_kw = kw
        return response
    _fn.last_model = None
    return _fn


# ---------------------------------------------------------------------------
def test_text_only_completion_normalized(monkeypatch):
    fn = fake_completion(_resp(_msg(content="The license check is at 0x401234.")))
    prov = LiteLLMProvider(model="gpt-4o-mini", completion_fn=fn, api_key="test-fake-key")
    r = prov.complete([{"role": "user", "content": "where is the check?"}])
    assert isinstance(r, LLMResponse)
    assert r.content == "The license check is at 0x401234."
    assert r.tool_calls == []


def test_tool_calls_parsed_with_json_arguments(monkeypatch):
    fn = fake_completion(_resp(_msg(
        content=None,
        tool_calls=[{"name": "decompile_function",
                     "arguments": json.dumps({"addr": "0x401234"})}],
    )))
    prov = LiteLLMProvider(model="m", completion_fn=fn)
    r = prov.complete([{"role": "user", "content": "go"}])
    assert len(r.tool_calls) == 1
    tc = r.tool_calls[0]
    assert tc.name == "decompile_function"
    assert tc.arguments == {"addr": "0x401234"}
    assert tc.id == "call_0"


def test_malformed_tool_arguments_falls_back_to_empty_dict():
    fn = fake_completion(_resp(_msg(
        content=None,
        tool_calls=[{"name": "list_functions", "arguments": "not json{"}],
    )))
    prov = LiteLLMProvider(model="m", completion_fn=fn)
    r = prov.complete([{"role": "user", "content": "x"}])
    assert r.tool_calls[0].arguments == {}


def test_forwards_model_messages_tools_to_completion_fn():
    fn = fake_completion(_resp(_msg(content="ok")))
    prov = LiteLLMProvider(model="claude-3-5-sonnet", completion_fn=fn, api_key="test-fake-key")
    tools = [{"type": "function", "function": {"name": "f", "parameters": {}}}]
    prov.complete([{"role": "user", "content": "hi"}], tools=tools, temperature=0.5)
    assert fn.last_model == "claude-3-5-sonnet"
    assert fn.last_messages == [{"role": "user", "content": "hi"}]
    assert fn.last_tools == tools
    assert fn.last_kw["temperature"] == 0.5


def test_forwards_api_base_to_completion_fn():
    # OpenAI-compatible endpoint (e.g. W&B Inference) needs a custom base URL.
    fn = fake_completion(_resp(_msg(content="ok")))
    prov = LiteLLMProvider(model="openai/zai-org/GLM-5.2", completion_fn=fn,
                           api_key="test-wandb-fake-key", api_base="https://api.inference.wandb.ai/v1")
    prov.complete([{"role": "user", "content": "hi"}])
    assert fn.last_kw["api_base"] == "https://api.inference.wandb.ai/v1"
    assert fn.last_kw["api_key"] == "test-wandb-fake-key"


def test_no_api_base_when_not_set():
    fn = fake_completion(_resp(_msg(content="ok")))
    prov = LiteLLMProvider(model="gpt-4o-mini", completion_fn=fn, api_key="test-fake-key")
    prov.complete([{"role": "user", "content": "hi"}])
    assert "api_base" not in fn.last_kw


def test_missing_litellm_without_completion_fn_raises(monkeypatch):
    # Force the litellm import to fail so the default completion_fn cannot resolve.
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "litellm":
            raise ImportError("no litellm")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(RuntimeError) as exc:
        LiteLLMProvider(model="m")
    assert "litellm" in str(exc.value).lower()
