"""Tests for mcp_servers.deobfuscation.server — the FastMCP deobfuscation tool layer."""
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
from mcp_servers.deobfuscation import server  # noqa: E402


def _write(tmp_path, name, raw):
    p = tmp_path / name
    p.write_bytes(raw)
    return p


def test_load_target_degrades_without_qiling(tmp_path):
    p = _write(tmp_path, "packed.exe",
               bb.build_pe_header(bits=64, machine=bb.IMAGE_FILE_MACHINE_AMD64))
    res = server.tool_load_target(str(p))
    assert res.get("available") is False


def test_trace_execution_degrades(tmp_path):
    p = _write(tmp_path, "packed.exe",
               bb.build_pe_header(bits=64, machine=bb.IMAGE_FILE_MACHINE_AMD64))
    res = server.tool_trace_execution(str(p), max_steps=100)
    assert res.get("available") is False
    assert res["trace"] == []


def test_lift_vm_handler_returns_spec():
    res = server.tool_lift_vm_handler(dispatch_addr=0x402000, opcode=0x01,
                                      name="vm_add", effects="reg[A]+=reg[B]")
    assert "0x01" in res["opcodes"]
    assert res["opcodes"]["0x01"]["name"] == "vm_add"


def test_disassemble_vm_bytecode_via_server():
    spec = server.tool_lift_vm_handler(dispatch_addr=0x402000, opcode=0x02,
                                       name="vm_nop", effects="ip+=1")
    disasm = server.tool_disassemble_vm_bytecode(spec, bytecode=bytes([0x02, 0x7F]))
    assert disasm[0]["opcode_name"] == "vm_nop"
    assert disasm[1]["opcode_name"] == "unknown"


def test_reconstruct_native_via_server():
    trace = [{"pc": 0x401000, "mnemonic": "ret", "op_str": ""}]
    res = server.tool_reconstruct_native(trace, dedup=True)
    assert res[0]["mnemonic"] == "ret"


def test_hybrid_solve_via_server():
    res = server.tool_hybrid_solve(
        trace=[{"pc": 0x401000, "mnemonic": "cmp", "op_str": "eax,0x7"}],
        predicate_str="lambda x: x == bytes([7])",
        input_length=1, alphabet_start=0, alphabet_end=16)
    assert res["found"] is True
    assert res["input"] == [7]
    assert res["narrowed_by_trace"] is True


def test_server_has_mcp_and_tools():
    assert hasattr(server, "mcp")
    for name in ("tool_load_target", "tool_trace_execution", "tool_lift_vm_handler",
                 "tool_disassemble_vm_bytecode", "tool_reconstruct_native",
                 "tool_hybrid_solve", "tool_build_vm_spec"):
        assert callable(getattr(server, name))
