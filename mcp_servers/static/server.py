"""Static MCP server (FastMCP).

Exposes the static-analysis tool layer. Each tool routes across engines:
- decompile / list_functions / xrefs: Ghidra (pyghidra) first, then r2, then unavailable.
- disassemble: capstone fallback (always available, r2-independent).
- strings / resolve_symbol / search_pattern: r2 first, then pure-Python fallback.

Run as a stdio MCP server:  python -m mcp_servers.static.server
"""
from __future__ import annotations

from pathlib import Path

from mcp.server.fastmcp import FastMCP

from tools.binary import analyze
from mcp_servers.static import ghidra_backend, r2_backend

mcp = FastMCP("re-static")


# ---------------------------------------------------------------------------
# Tool implementations (callable directly AND via @mcp.tool()).
# ---------------------------------------------------------------------------
def tool_load_binary(path: str) -> dict:
    """Detect format/arch/metadata of a binary."""
    return analyze(path).__dict__


def tool_list_functions(path: str) -> dict:
    """List functions: Ghidra -> r2 -> unavailable."""
    res = ghidra_backend.list_functions(path)
    if res.get("available"):
        return res
    r2 = r2_backend.list_functions(path)
    if r2.get("available"):
        return r2
    return {"available": False,
            "error": "no static engine (Ghidra/r2) installed; cannot list functions",
            "functions": []}


def tool_decompile_function(path: str, addr) -> dict:
    """Decompile a function at addr. Ghidra-only; hints to use disassemble otherwise."""
    res = ghidra_backend.decompile_function(path, addr)
    if res.get("available"):
        return res
    return {
        "available": False,
        "error": "Ghidra not installed; decompilation unavailable",
        "hint": "use the disassemble tool (capstone fallback) to read the raw instructions",
        "decompilation": "",
    }


def tool_disassemble(path: str, *, addr: int = 0, count: int = 64,
                     arch: str = "x86_64", bits: int = 64, file_offset: int = 0) -> dict:
    """Disassemble bytes (capstone fallback, always available)."""
    return r2_backend.disassemble(path, addr=addr, count=count, arch=arch,
                                  bits=bits, file_offset=file_offset)


def tool_xrefs_to(path: str, addr) -> dict:
    """Find references to an address: Ghidra -> r2 -> unavailable."""
    res = ghidra_backend.xrefs_to(path, addr)
    if res.get("available"):
        return res
    r2 = r2_backend.xrefs_to(path, addr)
    if r2.get("available"):
        return r2
    return {"available": False, "error": "no engine available for xrefs", "xrefs": []}


def tool_strings(path: str, min_len: int = 4) -> dict:
    """Extract strings: r2 -> pure-Python fallback."""
    return r2_backend.strings(path, min_len=min_len)


def tool_resolve_symbol(path: str, name: str) -> dict:
    """Resolve a symbol name to an address. r2-only; degrades without it."""
    r2 = r2_backend._open_r2(path)
    if r2 is None:
        return {"available": False, "error": "r2 not installed", "addr": None}
    try:
        raw = r2.cmd(f"?v sym.{name}")
        r2.quit()
        return {"available": True, "name": name, "addr": raw.strip() or None}
    except Exception as exc:  # noqa: BLE001
        r2.quit()
        return {"available": False, "error": str(exc), "addr": None}


def tool_search_pattern(path: str, pattern: str) -> dict:
    """Search for a byte pattern (hex, space-separated). r2 -> pure-Python fallback."""
    import binascii
    data = Path(path).read_bytes()
    try:
        needle = binascii.unhexlify(pattern.replace(" ", ""))
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "error": f"bad pattern: {exc}", "matches": []}

    matches: list[dict] = []
    start = 0
    while True:
        idx = data.find(needle, start)
        if idx < 0:
            break
        matches.append({"offset": idx})
        start = idx + 1
    return {"available": True, "pattern": pattern, "matches": matches}


# ---------------------------------------------------------------------------
# Register with the MCP instance.
# ---------------------------------------------------------------------------
@mcp.tool()
def load_binary(path: str) -> dict:
    """Detect the format, architecture, bit-width, entry point, and metadata of a binary."""
    return tool_load_binary(path)


@mcp.tool()
def list_functions(path: str) -> dict:
    """List functions discovered by Ghidra (or r2). Returns available flag + functions."""
    return tool_list_functions(path)


@mcp.tool()
def decompile_function(path: str, addr: str) -> dict:
    """Decompile a function at an address using Ghidra. Falls back to disassembly hints."""
    return tool_decompile_function(path, addr)


@mcp.tool()
def disassemble(path: str, addr: int = 0, count: int = 64,
                arch: str = "x86_64", bits: int = 64, file_offset: int = 0) -> dict:
    """Disassemble raw bytes at a virtual address (capstone fallback, always available)."""
    return tool_disassemble(path, addr=addr, count=count, arch=arch,
                            bits=bits, file_offset=file_offset)


@mcp.tool()
def xrefs_to(path: str, addr: str) -> dict:
    """Find cross-references to an address (Ghidra -> r2)."""
    return tool_xrefs_to(path, addr)


@mcp.tool()
def strings(path: str, min_len: int = 4) -> dict:
    """Extract ASCII strings and entropy (r2 -> pure-Python fallback)."""
    return tool_strings(path, min_len)


@mcp.tool()
def resolve_symbol(path: str, name: str) -> dict:
    """Resolve a symbol name to an address (r2)."""
    return tool_resolve_symbol(path, name)


@mcp.tool()
def search_pattern(path: str, pattern: str) -> dict:
    """Search a binary for a hex byte pattern (e.g. '41 41 41 41')."""
    return tool_search_pattern(path, pattern)


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
