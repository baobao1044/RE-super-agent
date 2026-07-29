"""Tests for agent.specialists.static — the static analysis specialist.

Runs a ReAct loop over the static MCP tools, captures discovered functions / strings,
and writes them into the shared workspace. Tests inject a scripted provider and a
registry backed by the real static server.tool_* functions (no transport needed).
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
from agent.specialists.static import StaticSpecialist  # noqa: E402


class ScriptedProvider:
    def __init__(self, responses):
        self._r = list(responses)
        self.calls = 0

    def complete(self, messages, tools=None, **kw):
        self.calls += 1
        return self._r.pop(0)


def make_registry(binary_path):
    from mcp_servers.static import server

    return {
        "load_binary": lambda a: server.tool_load_binary(binary_path),
        "list_functions": lambda a: server.tool_list_functions(binary_path),
        "decompile_function": lambda a: server.tool_decompile_function(binary_path, a.get("addr", "0x0")),
        "disassemble": lambda a: server.tool_disassemble(binary_path, addr=a.get("addr", 0),
                                                         count=a.get("count", 32),
                                                         arch=a.get("arch", "x86_64"),
                                                         bits=a.get("bits", 64),
                                                         file_offset=a.get("file_offset", 0)),
        "xrefs_to": lambda a: server.tool_xrefs_to(binary_path, a.get("addr", "0x0")),
        "strings": lambda a: server.tool_strings(binary_path, a.get("min_len", 4)),
        "search_pattern": lambda a: server.tool_search_pattern(binary_path, a.get("pattern", "")),
        "resolve_symbol": lambda a: server.tool_resolve_symbol(binary_path, a.get("name", "")),
    }


def _write(tmp_path, name, raw):
    p = tmp_path / name
    p.write_bytes(raw)
    return p


def test_static_specialist_loads_binary_and_records_strings(tmp_path):
    raw = bb.append_markers(
        bb.build_pe_header(bits=64, machine=bb.IMAGE_FILE_MACHINE_AMD64),
        [b"check_password", b"license_key"],
    )
    p = _write(tmp_path, "target.exe", raw)
    info = analyze(p)
    ws = Workspace(session_id="t1")
    ws.set_binary(info, risk_level="LOW")

    prov = ScriptedProvider([
        LLMResponse(content=None, tool_calls=[
            ToolCall(name="strings", arguments={"min_len": 4}, id="1"),
        ]),
        LLMResponse(content="Found strings: check_password, license_key."),
    ])
    spec = StaticSpecialist(provider=prov, tools_registry=make_registry(p))
    report = spec.run(task="find interesting strings", binary_path=p, workspace=ws)

    assert "check_password" in report["strings"]
    # workspace recorded the strings as a finding
    assert any("check_password" in f["summary"] for f in ws.findings)


def test_static_specialist_disassembles_and_records_instructions(tmp_path):
    code = bytes([0x48, 0x31, 0xC0, 0xC3])  # xor rax,rax; ret
    p = _write(tmp_path, "c.bin", code)
    info = analyze(p)
    ws = Workspace(session_id="t2")
    ws.set_binary(info, risk_level="LOW")

    prov = ScriptedProvider([
        LLMResponse(content=None, tool_calls=[
            ToolCall(name="disassemble", arguments={"addr": 0, "count": 8}, id="1"),
        ]),
        LLMResponse(content="The code clears rax and returns."),
    ])
    spec = StaticSpecialist(provider=prov, tools_registry=make_registry(p))
    report = spec.run(task="disassemble the entry", binary_path=p, workspace=ws)

    assert "instructions" in report
    mnems = [i["mnemonic"] for i in report["instructions"]]
    assert "xor" in mnems and "ret" in mnems


def test_static_specialist_system_prompt_mentions_static_tools(tmp_path):
    spec = StaticSpecialist(provider=ScriptedProvider([]), tools_registry={})
    assert "static" in spec.system_prompt.lower()
    assert "disassembl" in spec.system_prompt.lower() or "decompil" in spec.system_prompt.lower()


def test_static_specialist_search_pattern_records_match(tmp_path):
    raw = bb.append_markers(b"\x90", [b"\x41\x41\x41\x41"])
    p = _write(tmp_path, "c.bin", raw)
    info = analyze(p)
    ws = Workspace(session_id="t3")
    ws.set_binary(info, risk_level="LOW")

    prov = ScriptedProvider([
        LLMResponse(content=None, tool_calls=[
            ToolCall(name="search_pattern", arguments={"pattern": "41 41 41 41"}, id="1"),
        ]),
        LLMResponse(content="Pattern found at one offset."),
    ])
    spec = StaticSpecialist(provider=prov, tools_registry=make_registry(p))
    report = spec.run(task="search for marker bytes", binary_path=p, workspace=ws)
    assert report["matches"] and len(report["matches"]) >= 1
