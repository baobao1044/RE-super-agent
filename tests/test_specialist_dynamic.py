"""Tests for agent.specialists.dynamic — the dynamic analysis specialist.

The specialist runs anti-analysis detection FIRST (always available, static), writes
findings to the workspace, then runs a ReAct loop over the dynamic tools. Crucially, it
MUST refuse to spawn a process if the safety gate denies execution (HIGH risk or no
sandbox). Tests inject a scripted provider + registry backed by the real dynamic server
tool_* functions, and mock the safety decision.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
TESTS = ROOT / "tests"
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from fixtures import binary_builders as bb  # noqa: E402
from tools.binary import analyze  # noqa: E402
from agent.llm.provider import LLMResponse, ToolCall  # noqa: E402
from agent.state.workspace import Workspace  # noqa: E402
from agent.specialists.dynamic import DynamicSpecialist  # noqa: E402


class ScriptedProvider:
    def __init__(self, responses):
        self._r = list(responses)
        self.calls = 0

    def complete(self, messages, tools=None, **kw):
        self.calls += 1
        return self._r.pop(0)


def make_registry(binary_path):
    from mcp_servers.dynamic import server

    return {
        "detect_anti_analysis": lambda a: server.tool_detect_anti_analysis(binary_path),
        "recommend_handling": lambda a: server.tool_recommend_handling(a.get("anti_hints", [])),
        "spawn": lambda a: server.tool_spawn(binary_path, a.get("args", [])),
        "attach": lambda a: server.tool_attach(a.get("target", "")),
        "list_processes": lambda a: server.tool_list_processes(),
        "set_breakpoint": lambda a: server.tool_set_breakpoint(a.get("session", ""), a.get("location", "0x0")),
        "hook_function": lambda a: server.tool_hook_function(a.get("session", ""), a.get("addr", "0x0"), a.get("script", "")),
        "read_memory": lambda a: server.tool_read_memory(a.get("session", ""), a.get("addr", "0x0"), a.get("size", 16)),
        "get_regs": lambda a: server.tool_get_regs(a.get("session", "")),
    }


def _write(tmp_path, name, raw):
    p = tmp_path / name
    p.write_bytes(raw)
    return p


def test_dynamic_specialist_detects_anti_analysis_writes_workspace(tmp_path):
    raw = bb.append_markers(
        bb.build_pe_header(bits=64, machine=bb.IMAGE_FILE_MACHINE_AMD64),
        [b"IsDebuggerPresent", b"VMware"],
    )
    p = _write(tmp_path, "ad.exe", raw)
    info = analyze(p)
    ws = Workspace(session_id="t1")
    ws.set_binary(info, risk_level="LOW")

    prov = ScriptedProvider([
        LLMResponse(content=None, tool_calls=[ToolCall(name="detect_anti_analysis", arguments={}, id="1")]),
        LLMResponse(content="Detected anti-debug + anti-VM. Will apply handling before spawn."),
    ])
    spec = DynamicSpecialist(provider=prov, tools_registry=make_registry(p))
    report = spec.run(task="check for anti-analysis", binary_path=p, workspace=ws)

    assert "anti_debug" in report["anti_hints"]
    assert "anti_vm" in report["anti_hints"]
    assert any("anti_debug" in f["summary"] for f in ws.findings)


def test_dynamic_specialist_refuses_spawn_when_safety_denies(tmp_path, monkeypatch):
    """If the safety gate denies execution (e.g. HIGH risk), the specialist must NOT
    even attempt to call spawn."""
    p = _write(tmp_path, "evil.sys",
               bb.build_pe_header(bits=64, machine=bb.IMAGE_FILE_MACHINE_AMD64))
    info = analyze(p)
    ws = Workspace(session_id="t2")
    ws.set_binary(info, risk_level="HIGH")

    spawn_called = {"v": False}

    class TrackingRegistry(dict):
        def execute(self, name, arguments):
            if name == "spawn":
                spawn_called["v"] = True
            return super().execute(name, arguments) if name in self else {"error": "unknown"}

    reg = TrackingRegistry(make_registry(p))
    prov = ScriptedProvider([
        LLMResponse(content=None, tool_calls=[ToolCall(name="spawn", arguments={}, id="1")]),
        LLMResponse(content="Cannot spawn; safety gate denied execution for HIGH risk."),
    ])
    spec = DynamicSpecialist(provider=prov, tools_registry=reg)

    # Deny via the safety decision the specialist consults.
    from agent.core import safety
    from agent.core.safety import ExecutionDecision
    monkeypatch.setattr(safety, "decide", lambda info, risk_assessment=None: ExecutionDecision(
        allowed=False, mode="static_only", risk_level="HIGH",
        requires_confirmation=False, reason="HIGH risk refused"))

    report = spec.run(task="run the binary dynamically", binary_path=p, workspace=ws)
    assert spawn_called["v"] is False
    assert report.get("executed") is False
    assert "refused" in report.get("reason", "").lower() or "static" in report.get("reason", "").lower()


def test_dynamic_specialist_system_prompt_mentions_safety(tmp_path):
    spec = DynamicSpecialist(provider=ScriptedProvider([]), tools_registry={})
    assert "safety" in spec.system_prompt.lower() or "refuse" in spec.system_prompt.lower()
    assert "anti" in spec.system_prompt.lower()
