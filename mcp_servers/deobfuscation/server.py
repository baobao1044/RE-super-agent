"""Deobfuscation MCP server (FastMCP).

Exposes the deobfuscation tool layer: qiling-backed load/trace (degrade when missing) +
pure-logic VM lifting / disassembly / trace-driven reconstruction / hybrid solve (always
available). The specialist and workflow engine use these to devirtualize VM-based
obfuscators without symbolic path explosion.

Run as a stdio MCP server:  python -m mcp_servers.deobfuscation.server
"""
from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from mcp_servers.deobfuscation import qiling_backend, trace_reconstruct, vm_lifter

mcp = FastMCP("re-deobfuscation")

_EVAL_NAMESPACE = {"bytes": bytes, "len": len, "ord": ord, "chr": chr,
                   "range": range, "list": list}


def _compile_predicate(predicate_str: str):
    if not predicate_str.strip().startswith("lambda"):
        raise ValueError("predicate must be a lambda expression")
    return eval(predicate_str, dict(_EVAL_NAMESPACE), {})  # noqa: S307


# ---------------------------------------------------------------------------
# qiling-backed (degrade)
# ---------------------------------------------------------------------------
def tool_load_target(path: str, *, rootfs: str = "", arch: str = "",
                     osname: str = "") -> dict:
    return qiling_backend.load_target(path, rootfs=rootfs, arch=arch, osname=osname)


def tool_trace_execution(path: str, *, start_addr: int | None = None,
                         end_addr: int | None = None, max_steps: int = 10000) -> dict:
    return qiling_backend.trace_execution(path, start_addr=start_addr,
                                          end_addr=end_addr, max_steps=max_steps)


# ---------------------------------------------------------------------------
# pure-logic VM lifting + trace reconstruction (always available)
# ---------------------------------------------------------------------------
def tool_lift_vm_handler(dispatch_addr: int, opcode: int, name: str,
                         effects: str, handler_addr: int | None = None) -> dict:
    spec = vm_lifter.new_spec(dispatch_addr=dispatch_addr)
    vm_lifter.lift_handler(spec, opcode=opcode, name=name, effects=effects,
                           handler_addr=handler_addr)
    return spec


def tool_build_vm_spec(dispatch_addr: int, handlers: list[dict]) -> dict:
    """Build a full VM spec from a list of {opcode, name, effects} handler entries."""
    spec = vm_lifter.new_spec(dispatch_addr=dispatch_addr)
    for h in handlers:
        vm_lifter.lift_handler(spec, opcode=h["opcode"], name=h["name"],
                               effects=h.get("effects", ""),
                               handler_addr=h.get("handler_addr"))
    return spec


def tool_disassemble_vm_bytecode(spec: dict, bytecode: str | bytes) -> list[dict]:
    data = bytes(bytecode, "latin1") if isinstance(bytecode, str) else bytes(bytecode)
    return vm_lifter.disassemble_vm_bytecode(spec, data)


def tool_reconstruct_native(trace: list[dict], dedup: bool = False) -> list[dict]:
    return trace_reconstruct.reconstruct_native(trace, dedup=dedup)


def tool_hybrid_solve(trace: list[dict], predicate_str: str, input_length: int,
                      alphabet_start: int = 0, alphabet_end: int = 256) -> dict:
    pred = _compile_predicate(predicate_str)
    return trace_reconstruct.hybrid_solve(
        trace=trace, predicate=pred, input_length=input_length,
        alphabet=range(alphabet_start, alphabet_end))


def tool_recover_python_source(path: str, *, max_disasm_lines: int = 80) -> dict:
    """Recover the structure of a Python-protector-obfuscated file WITHOUT executing it.

    Currently supports enphysic.pro / Ngocuyencoder: deserialize the LZMA+base64 custom
    marshal payload into a reconstructed code object, then return a structured summary
    (names, constants, capped bytecode disassembly, nested scopes). Never exec()s —
    pure static inspection. Returns {available, protector, python_version, top_code}.
    """
    try:
        from tools.eps_deobf import recover_source_summary
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "error": f"deobfuscator import failed: {exc}"}
    try:
        return recover_source_summary(path, max_disasm_lines=max_disasm_lines)
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "error": f"{type(exc).__name__}: {exc}"}


def tool_decompile_python_source(path: str, *, decompiler: str = "pycdc",
                                 timeout: int = 60) -> dict:
    """Recover readable Python SOURCE from a Python-protector-obfuscated file.

    Deserializes the protected code object (never executes it) and lifts the bytecode
    back to Python source via a structural decompiler (always works on 3.11; an external
    decompiler is preferred if installed and version-compatible). Returns
    {available, source, decompiler, protector, python_version, source_chars}.
    """
    try:
        from tools.decompile_lifter import decompile_python_source as _decomp
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "error": f"decompiler import failed: {exc}"}
    try:
        return _decomp(path, decompiler=decompiler, timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "error": f"{type(exc).__name__}: {exc}"}


# ---------------------------------------------------------------------------
@mcp.tool()
def load_target(path: str, rootfs: str = "", arch: str = "", osname: str = "") -> dict:
    """Load a binary into Qiling for safe emulation (degrades if qiling missing)."""
    return tool_load_target(path, rootfs=rootfs, arch=arch, osname=osname)


@mcp.tool()
def trace_execution(path: str, start_addr: int | None = None,
                    end_addr: int | None = None, max_steps: int = 10000) -> dict:
    """Emulate a binary and return a (pc, mnemonic) execution trace."""
    return tool_trace_execution(path, start_addr=start_addr,
                                end_addr=end_addr, max_steps=max_steps)


@mcp.tool()
def lift_vm_handler(dispatch_addr: int, opcode: int, name: str,
                    effects: str, handler_addr: int | None = None) -> dict:
    """Record the semantics of a single VM opcode into a VM spec."""
    return tool_lift_vm_handler(dispatch_addr, opcode, name, effects, handler_addr)


@mcp.tool()
def build_vm_spec(dispatch_addr: int, handlers: list[dict]) -> dict:
    """Build a full VM spec from multiple lifted handlers."""
    return tool_build_vm_spec(dispatch_addr, handlers)


@mcp.tool()
def disassemble_vm_bytecode(spec: dict, bytecode: str) -> list[dict]:
    """Disassemble VM bytecode using a lifted VM spec."""
    return tool_disassemble_vm_bytecode(spec, bytecode)


@mcp.tool()
def reconstruct_native(trace: list[dict], dedup: bool = False) -> list[dict]:
    """Reconstruct native ops from a concrete execution trace."""
    return tool_reconstruct_native(trace, dedup)


@mcp.tool()
def hybrid_solve(trace: list[dict], predicate_str: str, input_length: int,
                 alphabet_start: int = 0, alphabet_end: int = 256) -> dict:
    """Trace-narrowed hybrid solve: narrow by trace then run the pure constraint solver."""
    return tool_hybrid_solve(trace, predicate_str, input_length, alphabet_start, alphabet_end)


@mcp.tool()
def recover_python_source(path: str, max_disasm_lines: int = 80) -> dict:
    """Recover the structure of a Python-protector-obfuscated file without executing it
    (supports enphysic.pro / Ngocuyencoder: base64+LZMA+custom marshal)."""
    return tool_recover_python_source(path, max_disasm_lines=max_disasm_lines)


@mcp.tool()
def decompile_python_source(path: str, decompiler: str = "pycdc",
                            timeout: int = 60) -> dict:
    """Recover readable Python SOURCE from a Python-protector-obfuscated file
    (supports enphysic.pro / Ngocuyencoder). Deserializes the protected code object
    without executing it and lifts the bytecode back to Python source."""
    return tool_decompile_python_source(path, decompiler=decompiler, timeout=timeout)


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
