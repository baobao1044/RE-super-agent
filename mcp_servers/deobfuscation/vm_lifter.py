"""VM handler lifting — recover opcode semantics from a VM-based obfuscator.

A VM obfuscator (VMProtect/Themida/custom) encodes real code as bytecode interpreted by a
dispatcher + handler table. Lifting means: analyze each handler, recover what its opcode
does (effects), and record it in a "VM spec". The spec then lets us disassemble the
encoded bytecode back to something meaningful.

This module is the pure-logic core (LLM-assisted reasoning feeds it via the specialist).
The qiling/unicorn backends (trace_reconstruct) provide the concrete traces that refine
the spec. No engine is required here.
"""
from __future__ import annotations


def new_spec(dispatch_addr: int) -> dict:
    """Create an empty VM spec anchored at the dispatcher address."""
    return {
        "dispatch_addr": dispatch_addr,
        "opcodes": {},          # hex(opcode) -> {name, effects}
        "register_count": 0,
        "handler_table": [],    # [{opcode, handler_addr}]
    }


def _opcode_key(opcode: int) -> str:
    return f"0x{opcode:02x}"


def lift_handler(spec: dict, *, opcode: int, name: str, effects: str,
                 handler_addr: int | None = None) -> dict:
    """Record (or refine) the semantics of a single VM opcode.

    Lifting the same opcode again overwrites it (refinement as the analysis improves).
    """
    key = _opcode_key(opcode)
    entry = {"opcode": opcode, "name": name, "effects": effects}
    if handler_addr is not None:
        entry["handler_addr"] = handler_addr
        spec["handler_table"].append({"opcode": opcode, "handler_addr": handler_addr})
    spec["opcodes"][key] = entry
    return spec


def disassemble_vm_bytecode(spec: dict, bytecode: bytes) -> list[dict]:
    """Walk the bytecode, labeling each byte with the lifted opcode name (or 'unknown')."""
    opcodes = spec.get("opcodes", {})
    out = []
    for i, b in enumerate(bytecode):
        entry = opcodes.get(_opcode_key(b))
        out.append({
            "offset": i,
            "byte": b,
            "opcode_name": entry["name"] if entry else "unknown",
            "effects": entry.get("effects", "") if entry else "",
        })
    return out


def vm_spec_completeness(spec: dict) -> dict:
    """Report how complete the lifted spec is (opcodes seen vs unknown in a sample)."""
    return {
        "lifted_opcodes": len(spec.get("opcodes", {})),
        "dispatch_addr": spec.get("dispatch_addr"),
        "handlers": len(spec.get("handler_table", [])),
    }
