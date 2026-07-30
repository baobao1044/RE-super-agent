"""Provider-agnostic LLM client.

LiteLLMProvider wraps a completion function (litellm.completion by default) and
normalizes the OpenAI-shaped response into a uniform LLMResponse (content +
parsed tool_calls). Tests and specialists inject a fake completion_fn so no
network or litellm install is required.

The contract every specialist/supervisor depends on:
    r = provider.complete(messages, tools=...)
    r.content        -> str (assistant text, may be "")
    r.tool_calls     -> list[ToolCall(name, arguments: dict, id)]
    r.stop_reason    -> str
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class ToolCall:
    name: str
    arguments: dict = field(default_factory=dict)
    id: str = ""


@dataclass
class LLMResponse:
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    stop_reason: str = ""
    raw: Any = None


def _default_completion_fn():
    """Resolve litellm.completion, or raise a clear error if litellm is absent."""
    try:
        import litellm  # type: ignore
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(
            "litellm is required for LLM calls. Install with `pip install litellm`, "
            "or inject a custom completion_fn."
        ) from exc
    return litellm.completion


class LLMProvider:
    """Base interface."""

    def complete(self, messages, tools=None, **kwargs) -> LLMResponse:  # pragma: no cover
        raise NotImplementedError


class LiteLLMProvider(LLMProvider):
    def __init__(self, model, *, api_key=None, api_base=None, completion_fn=None,
                 temperature=0.2, max_tokens=4096, timeout=120):
        self.model = model
        self.api_key = api_key
        self.api_base = api_base
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout
        if completion_fn is None:
            completion_fn = _default_completion_fn()
        self._completion = completion_fn

    def complete(self, messages, tools=None, **kwargs) -> LLMResponse:
        call_kwargs = {
            "model": self.model,
            "messages": messages,
            "temperature": kwargs.pop("temperature", self.temperature),
            "max_tokens": kwargs.pop("max_tokens", self.max_tokens),
            "timeout": kwargs.pop("timeout", self.timeout),
        }
        if self.api_key:
            call_kwargs["api_key"] = self.api_key
        if self.api_base:
            call_kwargs["api_base"] = self.api_base
        if tools:
            call_kwargs["tools"] = tools
        call_kwargs.update(kwargs)

        raw = self._completion(**call_kwargs)
        return self._normalize(raw)

    @staticmethod
    def _normalize(raw) -> LLMResponse:
        choices = _get(raw, "choices")
        if not choices:
            return LLMResponse(raw=raw)
        choice = choices[0]
        message = _get(choice, "message")
        content = _get(message, "content") or ""
        stop_reason = _get(choice, "finish_reason") or ""

        tool_calls = []
        raw_calls = _get(message, "tool_calls") or []
        for rc in raw_calls:
            fn = _get(rc, "function") or {}
            name = _get(fn, "name") or _get(rc, "name") or ""
            args_raw = _get(fn, "arguments")
            if isinstance(args_raw, dict):
                args = args_raw
            elif isinstance(args_raw, str):
                try:
                    args = json.loads(args_raw)
                except Exception:  # noqa: BLE001
                    args = {}
            else:
                args = {}
            tool_calls.append(ToolCall(name=name, arguments=args, id=_get(rc, "id") or ""))

        return LLMResponse(content=content, tool_calls=tool_calls,
                           stop_reason=stop_reason, raw=raw)


def _get(obj, key, default=None):
    """Attribute-or-item access for both dicts and namespaces."""
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)
