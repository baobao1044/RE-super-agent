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


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
