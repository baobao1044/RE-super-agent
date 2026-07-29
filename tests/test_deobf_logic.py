"""Tests for mcp_servers.deobfuscation VM lifter + trace-driven devirtualization.

These exercise the pure-Python logic (no qiling/unicorn needed): lifting a trivial VM's
opcode semantics into a spec, disassembling VM bytecode via the spec, and reconstructing
native ops from a concrete execution trace (the trace-driven hybrid that avoids symbolic
path explosion).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from mcp_servers.deobfuscation import vm_lifter, trace_reconstruct  # noqa: E402


# ---------------------------------------------------------------------------
# VM spec lifting
# ---------------------------------------------------------------------------
def test_lift_handler_records_opcode_semantics():
    spec = vm_lifter.new_spec(dispatch_addr=0x402000)
    vm_lifter.lift_handler(spec, opcode=0x01, name="vm_add",
                           effects="reg[A] = reg[A] + reg[B]; ip += 3")
    assert "0x01" in spec["opcodes"]
    assert spec["opcodes"]["0x01"]["name"] == "vm_add"
    assert spec["opcodes"]["0x01"]["effects"] == "reg[A] = reg[A] + reg[B]; ip += 3"


def test_lift_handler_overwrites_existing_opcode():
    spec = vm_lifter.new_spec(dispatch_addr=0x402000)
    vm_lifter.lift_handler(spec, opcode=0x01, name="vm_add", effects="ip+=3")
    vm_lifter.lift_handler(spec, opcode=0x01, name="vm_add_refined", effects="reg[A]+=reg[B]; ip+=3")
    assert spec["opcodes"]["0x01"]["name"] == "vm_add_refined"


def test_disassemble_vm_bytecode_uses_spec():
    spec = vm_lifter.new_spec(dispatch_addr=0x402000)
    vm_lifter.lift_handler(spec, opcode=0x01, name="vm_add", effects="reg[A]+=reg[B]")
    vm_lifter.lift_handler(spec, opcode=0x02, name="vm_ret", effects="halt")
    disasm = vm_lifter.disassemble_vm_bytecode(spec, bytecode=bytes([0x01, 0xAA, 0xBB, 0x02]))
    names = [i["opcode_name"] for i in disasm]
    assert "vm_add" in names
    assert "vm_ret" in names


def test_disassemble_vm_bytecode_unknown_opcode_marked():
    spec = vm_lifter.new_spec(dispatch_addr=0x402000)  # no opcodes lifted
    disasm = vm_lifter.disassemble_vm_bytecode(spec, bytecode=bytes([0x7F, 0x00]))
    assert disasm[0]["opcode_name"] == "unknown"


# ---------------------------------------------------------------------------
# trace-driven devirtualization
# ---------------------------------------------------------------------------
def test_reconstruct_native_from_trace_basic():
    trace = [
        {"pc": 0x401000, "mnemonic": "mov", "op_str": "eax, 0x5"},
        {"pc": 0x401005, "mnemonic": "cmp", "op_str": "eax, 0x5"},
        {"pc": 0x401007, "mnemonic": "je", "op_str": "0x401010"},
    ]
    native = trace_reconstruct.reconstruct_native(trace)
    assert len(native) == 3
    assert native[0]["pc"] == 0x401000
    assert native[1]["mnemonic"] == "cmp"


def test_reconstruct_native_dedups_consecutive_identical_pcs():
    trace = [
        {"pc": 0x401000, "mnemonic": "mov", "op_str": "eax, 0x5"},
        {"pc": 0x401000, "mnemonic": "mov", "op_str": "eax, 0x5"},
        {"pc": 0x401005, "mnemonic": "ret", "op_str": ""},
    ]
    native = trace_reconstruct.reconstruct_native(trace, dedup=True)
    assert len(native) == 2  # the duplicate mov collapsed


def test_reconstruct_native_summarizes_trace():
    trace = [
        {"pc": 0x401000, "mnemonic": "mov", "op_str": "eax, 0x5"},
        {"pc": 0x401005, "mnemonic": "ret", "op_str": ""},
    ]
    summary = trace_reconstruct.summarize_trace(trace)
    assert summary["instruction_count"] == 2
    assert "mov" in summary["mnemonics_seen"]
    assert "ret" in summary["mnemonics_seen"]


def test_hybrid_solve_uses_trace_then_solver():
    trace = [{"pc": 0x401000, "mnemonic": "cmp", "op_str": "eax, 0x7"}]
    result = trace_reconstruct.hybrid_solve(
        trace=trace, predicate=lambda x: x == bytes([7]),
        input_length=1, alphabet=range(0, 16))
    assert result["found"] is True
    assert result["input"] == [7]
    assert result["narrowed_by_trace"] is True
