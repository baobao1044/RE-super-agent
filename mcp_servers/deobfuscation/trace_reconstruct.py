"""Trace-driven devirtualization — reconstruct native ops from a concrete execution trace.

Symbolic execution on a VM obfuscator explodes (each VM bytecode instruction branches
wildly). The hybrid strategy: record a CONCRETE trace (from Qiling/unicorn emulation or
Frida), then reconstruct the native semantics actually executed, narrowing the symbolic
search to the small slice that the trace exposed. This module is the pure-logic core.
"""
from __future__ import annotations

import itertools


def reconstruct_native(trace: list[dict], *, dedup: bool = False) -> list[dict]:
    """Roll a (pc, mnemonic, op_str) trace into the native instruction sequence actually run.

    With dedup=True, consecutive identical (pc, mnemonic, op_str) entries collapse (loops).
    """
    out: list[dict] = []
    for step in trace:
        entry = {"pc": step.get("pc"), "mnemonic": step.get("mnemonic", ""),
                 "op_str": step.get("op_str", "")}
        if dedup and out and out[-1] == entry:
            continue
        out.append(entry)
    return out


def summarize_trace(trace: list[dict]) -> dict:
    """Cheap stats over a trace: count, distinct mnemonics, jump targets."""
    mnemonics: dict[str, int] = {}
    for step in trace:
        m = step.get("mnemonic", "")
        mnemonics[m] = mnemonics.get(m, 0) + 1
    pcs = sorted({s.get("pc") for s in trace if s.get("pc") is not None})
    return {
        "instruction_count": len(trace),
        "mnemonics_seen": list(mnemonics),
        "mnemonic_counts": mnemonics,
        "pc_range": [pcs[0], pcs[-1]] if pcs else [],
    }


def hybrid_solve(*, trace: list[dict], predicate, input_length: int,
                 alphabet, narrowed_by_trace: bool = True) -> dict:
    """Narrow the search using the trace, then run the pure solver on the exposed slice.

    The trace tells us which addresses/inputs matter; here we simply run the bounded
    brute-force solver over `alphabet` (the real narrowing happens in the workflow engine
    which picks the address range from the trace before calling this).
    """
    alpha = list(alphabet)
    for combo in itertools.product(alpha, repeat=input_length):
        candidate = bytes(combo)
        try:
            if predicate(candidate):
                return {"found": True, "input": list(candidate),
                        "narrowed_by_trace": narrowed_by_trace, "engine": "hybrid_pure"}
        except Exception:  # noqa: BLE001
            continue
    return {"found": False, "narrowed_by_trace": narrowed_by_trace, "engine": "hybrid_pure"}
