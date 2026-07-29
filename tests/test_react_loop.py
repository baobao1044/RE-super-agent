"""Tests for agent.core.react_loop — the shared ReAct (reason/act/observe) primitive.

Every specialist runs this loop with its own tool registry + LLM provider. Tests inject
a scripted fake provider and a fake tool registry so no network or MCP server is needed.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent.core.react_loop import react_loop, Step  # noqa: E402
from agent.llm.provider import LLMResponse, ToolCall  # noqa: E402


class FakeProvider:
    """Returns a scripted sequence of LLMResponses, one per complete() call."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = 0

    def complete(self, messages, tools=None, **kw):
        self.calls += 1
        return self._responses.pop(0)


class FakeRegistry:
    """Maps tool name -> callable(result dict). Records calls."""

    def __init__(self, handlers=None):
        self._handlers = handlers or {}
        self.calls = []

    def execute(self, name, arguments):
        self.calls.append((name, arguments))
        return self._handlers.get(name, lambda a: {"ok": True})(arguments)


def test_text_only_answer_returns_final(monkeypatch):
    prov = FakeProvider([LLMResponse(content="The license check is at 0x401234.")])
    reg = FakeRegistry()
    result = react_loop(provider=prov, registry=reg, messages=[{"role": "user", "content": "where?"}],
                       tools=[])
    assert result.final_text == "The license check is at 0x401234."
    assert result.steps == []
    assert prov.calls == 1


def test_tool_call_then_answer_executes_tool_and_loops():
    prov = FakeProvider([
        LLMResponse(content=None, tool_calls=[
            ToolCall(name="decompile_function", arguments={"addr": "0x401234"}, id="c1"),
        ]),
        LLMResponse(content="That function compares the password to 'SECRET'."),
    ])
    reg = FakeRegistry(handlers={"decompile_function": lambda a: {"decomp": "cmp ... 'SECRET'"}})
    result = react_loop(provider=prov, registry=reg,
                       messages=[{"role": "user", "content": "analyze"}], tools=[])
    assert len(result.steps) == 1
    step = result.steps[0]
    assert step.tool_name == "decompile_function"
    assert step.tool_args == {"addr": "0x401234"}
    assert step.tool_result == {"decomp": "cmp ... 'SECRET'"}
    assert result.final_text == "That function compares the password to 'SECRET'."
    assert prov.calls == 2
    assert reg.calls[0] == ("decompile_function", {"addr": "0x401234"})


def test_tool_result_appended_to_history_for_next_call():
    """The tool's output must reach the model in the next complete() call."""
    seen = {}

    class RecProvider(FakeProvider):
        def complete(self, messages, tools=None, **kw):
            seen["last_messages"] = list(messages)
            return super().complete(messages, tools, **kw)

    prov = RecProvider([
        LLMResponse(content=None, tool_calls=[ToolCall(name="list_functions", arguments={}, id="c1")]),
        LLMResponse(content="done"),
    ])
    reg = FakeRegistry(handlers={"list_functions": lambda a: {"funcs": ["main", "check"]}})
    react_loop(provider=prov, registry=reg, messages=[{"role": "user", "content": "go"}], tools=[])
    msgs = seen["last_messages"]  # messages from the SECOND complete() call
    # The history must contain the user msg, the assistant tool_call, and a tool result.
    roles = [m["role"] for m in msgs]
    assert "assistant" in roles and "tool" in roles
    tool_msg = next(m for m in msgs if m["role"] == "tool")
    assert "main" in str(tool_msg["content"])


def test_multiple_tool_calls_in_one_turn_all_executed():
    prov = FakeProvider([
        LLMResponse(content=None, tool_calls=[
            ToolCall(name="strings", arguments={}, id="c1"),
            ToolCall(name="list_functions", arguments={}, id="c2"),
        ]),
        LLMResponse(content="finished"),
    ])
    reg = FakeRegistry()
    result = react_loop(provider=prov, registry=reg, messages=[{"role": "user", "content": "x"}], tools=[])
    assert len(result.steps) == 2
    assert {s.tool_name for s in result.steps} == {"strings", "list_functions"}


def test_max_steps_enforced_to_prevent_runaway():
    """If the model never stops calling tools, the loop must bail at max_steps."""
    prov = FakeProvider([
        LLMResponse(content=None, tool_calls=[ToolCall(name="t", arguments={}, id=f"c{i}")])
        for i in range(100)
    ])
    reg = FakeRegistry()
    result = react_loop(provider=prov, registry=reg, messages=[{"role": "user", "content": "x"}],
                       tools=[], max_steps=3)
    assert len(result.steps) <= 3
    assert result.truncated is True
    assert "max" in result.final_text.lower() or "truncat" in result.final_text.lower()


def test_tool_error_recorded_but_loop_continues():
    prov = FakeProvider([
        LLMResponse(content=None, tool_calls=[ToolCall(name="boom", arguments={}, id="c1")]),
        LLMResponse(content="recovered"),
    ])

    class ErrRegistry(FakeRegistry):
        def execute(self, name, arguments):
            raise RuntimeError("tool exploded")

    result = react_loop(provider=prov, registry=ErrRegistry(),
                        messages=[{"role": "user", "content": "x"}], tools=[])
    assert result.steps[0].tool_error is True
    assert "tool exploded" in str(result.steps[0].tool_result)
    assert result.final_text == "recovered"
