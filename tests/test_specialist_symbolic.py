"""Tests for agent.specialists.symbolic — the symbolic analysis specialist.

Runs a ReAct loop over the symbolic MCP tools and writes solved inputs / flags into the
workspace. Tests inject a scripted provider + registry backed by the real symbolic server
tool_* functions. The headline test: the specialist recovers a short flag ("CAT") from a
flag-checker predicate, writing it as a workspace finding.
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
from agent.specialists.symbolic import SymbolicSpecialist  # noqa: E402


class ScriptedProvider:
    def __init__(self, responses):
        self._r = list(responses)
        self.calls = 0

    def complete(self, messages, tools=None, **kw):
        self.calls += 1
        return self._r.pop(0)


def make_registry(binary_path):
    from mcp_servers.symbolic import server
    return {
        "load_project": lambda a: server.tool_load_project(binary_path),
        "explore_to": lambda a: server.tool_explore_to(binary_path, a.get("target_addr", 0x401000),
                                                      a.get("avoid", [])),
        "find_input_satisfying": lambda a: server.tool_find_input_satisfying(
            a.get("predicate_str", "lambda x: False"),
            a.get("input_length", 1),
            a.get("alphabet_start", 0), a.get("alphabet_end", 256)),
        "extract_flag": lambda a: server.tool_extract_flag(
            a.get("predicate_str", "lambda x: False"),
            a.get("expected_len", 3),
            a.get("alphabet_start", 65), a.get("alphabet_end", 91)),
        "get_state_info": lambda a: server.tool_get_state_info(binary_path),
    }


def _write(tmp_path, name, raw):
    p = tmp_path / name
    p.write_bytes(raw)
    return p


def test_symbolic_specialist_recovers_flag(tmp_path):
    p = _write(tmp_path, "flag_checker.elf",
               bb.build_elf_header(bits=64, machine=bb.EM_X86_64))
    info = analyze(p)
    ws = Workspace(session_id="t1")
    ws.set_binary(info, risk_level="LOW")

    prov = ScriptedProvider([
        LLMResponse(content=None, tool_calls=[
            ToolCall(name="extract_flag",
                     arguments={"predicate_str": "lambda x: x == b'CAT'",
                               "expected_len": 3,
                               "alphabet_start": 65, "alphabet_end": 91}, id="1"),
        ]),
        LLMResponse(content="Recovered flag: CAT"),
    ])
    spec = SymbolicSpecialist(provider=prov, tools_registry=make_registry(p))
    report = spec.run(task="recover the flag from the checker", binary_path=p, workspace=ws)

    assert report["found"] is True
    assert report["flag"] == "CAT"
    # workspace recorded the flag as a finding
    assert any("CAT" in f["summary"] for f in ws.findings)


def test_symbolic_specialist_finds_satisfying_input(tmp_path):
    p = _write(tmp_path, "crackme.elf", bb.build_elf_header(bits=64, machine=bb.EM_X86_64))
    info = analyze(p)
    ws = Workspace(session_id="t2")
    ws.set_binary(info, risk_level="LOW")

    prov = ScriptedProvider([
        LLMResponse(content=None, tool_calls=[
            ToolCall(name="find_input_satisfying",
                     arguments={"predicate_str": "lambda x: x == bytes([7])",
                                "input_length": 1,
                                "alphabet_start": 0, "alphabet_end": 16}, id="1"),
        ]),
        LLMResponse(content="Found satisfying input: 7"),
    ])
    spec = SymbolicSpecialist(provider=prov, tools_registry=make_registry(p))
    report = spec.run(task="find input satisfying the license check", binary_path=p, workspace=ws)
    assert report["found"] is True
    assert report["input"] == [7]
    assert any("7" in f["summary"] for f in ws.findings)


def test_symbolic_specialist_system_prompt_mentions_constraints(tmp_path):
    spec = SymbolicSpecialist(provider=ScriptedProvider([]), tools_registry={})
    assert "symbolic" in spec.system_prompt.lower() or "constraint" in spec.system_prompt.lower()
    assert "flag" in spec.system_prompt.lower()
