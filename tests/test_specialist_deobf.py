"""Tests for agent.specialists.deobfuscation — the deobfuscation specialist.

Runs a ReAct loop over the deobfuscation MCP tools, builds a VM spec in the workspace,
and devirtualizes a packed sample's bytecode. Tests inject a scripted provider + registry
backed by the real deobfuscation server tool_* functions.
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
from agent.specialists.deobfuscation import DeobfuscationSpecialist  # noqa: E402


class ScriptedProvider:
    def __init__(self, responses):
        self._r = list(responses)
        self.calls = 0

    def complete(self, messages, tools=None, **kw):
        self.calls += 1
        return self._r.pop(0)


def make_registry(binary_path):
    from mcp_servers.deobfuscation import server
    return {
        "load_target": lambda a: server.tool_load_target(binary_path),
        "trace_execution": lambda a: server.tool_trace_execution(binary_path, max_steps=a.get("max_steps", 100)),
        "lift_vm_handler": lambda a: server.tool_lift_vm_handler(
            a.get("dispatch_addr", 0x402000), a.get("opcode", 0),
            a.get("name", ""), a.get("effects", ""), a.get("handler_addr")),
        "build_vm_spec": lambda a: server.tool_build_vm_spec(
            a.get("dispatch_addr", 0x402000), a.get("handlers", [])),
        "disassemble_vm_bytecode": lambda a: server.tool_disassemble_vm_bytecode(
            a.get("spec", {"dispatch_addr": 0, "opcodes": {}}),
            a.get("bytecode", b"")),
        "reconstruct_native": lambda a: server.tool_reconstruct_native(
            a.get("trace", []), dedup=a.get("dedup", False)),
        "hybrid_solve": lambda a: server.tool_hybrid_solve(
            a.get("trace", []),
            a.get("predicate_str", "lambda x: False"),
            a.get("input_length", 1),
            a.get("alphabet_start", 0), a.get("alphabet_end", 256)),
    }


def _write(tmp_path, name, raw):
    p = tmp_path / name
    p.write_bytes(raw)
    return p


def test_deobf_specialist_lifts_vm_handlers_and_builds_spec(tmp_path):
    p = _write(tmp_path, "packed.exe", bb.append_markers(
        bb.build_pe_header(bits=64, machine=bb.IMAGE_FILE_MACHINE_AMD64), [b"VMProtect"]))
    info = analyze(p)
    ws = Workspace(session_id="t1")
    ws.set_binary(info, risk_level="MEDIUM")

    prov = ScriptedProvider([
        LLMResponse(content=None, tool_calls=[
            ToolCall(name="lift_vm_handler",
                     arguments={"dispatch_addr": 0x402000, "opcode": 0x01,
                                "name": "vm_add", "effects": "reg[A]+=reg[B]"}, id="1"),
            ToolCall(name="lift_vm_handler",
                     arguments={"dispatch_addr": 0x402000, "opcode": 0x02,
                                "name": "vm_ret", "effects": "halt"}, id="2"),
        ]),
        LLMResponse(content="Lifted two VM handlers (vm_add, vm_ret) into the VM spec."),
    ])
    spec = DeobfuscationSpecialist(provider=prov, tools_registry=make_registry(p))
    report = spec.run(task="lift the VM handlers", binary_path=p, workspace=ws)

    # workspace now holds the VM spec with two opcodes
    assert ws.vm_spec is not None
    assert "0x01" in ws.vm_spec["opcodes"]
    assert "0x02" in ws.vm_spec["opcodes"]
    assert report["lifted_opcodes"] >= 2


def test_deobf_specialist_disassembles_bytecode_with_workspace_spec(tmp_path):
    p = _write(tmp_path, "packed.exe",
               bb.build_pe_header(bits=64, machine=bb.IMAGE_FILE_MACHINE_AMD64))
    info = analyze(p)
    ws = Workspace(session_id="t2")
    ws.set_binary(info, risk_level="MEDIUM")
    # pre-populate the workspace VM spec (as if previously lifted)
    from mcp_servers.deobfuscation import server
    spec = server.tool_build_vm_spec(0x402000, [
        {"opcode": 0x01, "name": "vm_add", "effects": "reg[A]+=reg[B]"},
        {"opcode": 0x02, "name": "vm_ret", "effects": "halt"},
    ])
    ws.set_vm_spec(spec)

    prov = ScriptedProvider([
        LVM_step_disasm(),
        LLMResponse(content="Disassembled the VM bytecode; found vm_add then vm_ret."),
    ])
    spec_agent = DeobfuscationSpecialist(provider=prov, tools_registry=make_registry(p))
    report = spec_agent.run(task="disassemble the VM bytecode", binary_path=p, workspace=ws)
    names = [i["opcode_name"] for i in report["disassembly"]]
    assert "vm_add" in names and "vm_ret" in names


def LVM_step_disasm():
    """A scripted response that calls disassemble_vm_bytecode; the specialist injects the
    workspace VM spec. Bytecode 0x01 0x02 matches the lifted opcodes (vm_add, vm_ret)."""
    return LLMResponse(content=None, tool_calls=[
        ToolCall(name="disassemble_vm_bytecode",
                 arguments={"bytecode": "\x01\x02"}, id="1"),
    ])


def test_deobf_specialist_system_prompt_mentions_devirtualization(tmp_path):
    spec = DeobfuscationSpecialist(provider=ScriptedProvider([]), tools_registry={})
    assert "vm" in spec.system_prompt.lower()
    assert "devirtual" in spec.system_prompt.lower() or "trace" in spec.system_prompt.lower()
