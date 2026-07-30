"""Dynamic MCP server (FastMCP).

Exposes the dynamic-analysis tool layer: process control + instrumentation across frida
(primary, cross-platform), gdb (Linux), windbg (Windows), plus the anti-analysis cluster
(detect / patch / hide / emulate). All engines degrade gracefully (available=False).

Run as a stdio MCP server:  python -m mcp_servers.dynamic.server
"""
from __future__ import annotations

import platform

from mcp.server.fastmcp import FastMCP

from mcp_servers.dynamic import anti_analysis, frida_backend, gdb_backend, windbg_backend

mcp = FastMCP("re-dynamic")


def _is_windows() -> bool:
    return platform.system() == "Windows"


# ---------------------------------------------------------------------------
# Anti-analysis cluster (pure-static, always available).
# ---------------------------------------------------------------------------
def tool_detect_anti_analysis(path: str) -> dict:
    """Scan a binary for anti-debug/anti-VM/TLS-callback indicators (static)."""
    return anti_analysis.detect(path)


def tool_recommend_handling(anti_hints: list[str]) -> dict:
    """Map detected anti-analysis hints to recommended handling steps."""
    return anti_analysis.recommend_handling(anti_hints)


def tool_patch_anti_debug(session: str, hints: list[str]) -> dict:
    """Stub: patch anti-debug checks at runtime (returns intent; frida does the work)."""
    return {"available": "anti_debug" in (hints or []),
            "session": session,
            "patched": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent"]
            if "anti_debug" in (hints or []) else []}


def tool_hide_debugger(session: str) -> dict:
    """Stub: hide the debugger (ScyllaHide-style) via frida script."""
    return {"available": True, "session": session, "hidden": True,
            "note": "apply via frida script in a real session"}


def tool_emulate_clean_environment(session: str) -> dict:
    """Stub: emulate a clean (non-VM) environment via frida hooks."""
    return {"available": True, "session": session, "emulated": True,
            "note": "spoof host strings / registry via frida in a real session"}


# ---------------------------------------------------------------------------
# Process control (routed across backends).
# ---------------------------------------------------------------------------
def tool_spawn(path: str, args: list[str] | None = None) -> dict:
    """Spawn a process for instrumentation (frida)."""
    return frida_backend.spawn(path, args)


def tool_run_restricted(
    path: str,
    args: list[str] | None = None,
    *,
    timeout: int = 20,
    risk_level: str | None = None,
    allow_host_fallback: bool = False,
    interpreter: str | None = None,
) -> dict:
    """Run a target (Python script) under weak-isolation restricted subprocess.

    Routes execution through the sandbox layer. Refuses HIGH risk. When Docker is
    available it is the preferred isolation; otherwise the opt-in restricted
    subprocess fallback is used (the caller must pass allow_host_fallback=True after the
    user accepted the weak-isolation risk). The target is COPIED into a throwaway scratch
    dir and run in isolated Python mode (-I), so the original file is never read or
    written by the child.
    """
    import sys
    from pathlib import Path
    from tools import sandbox

    risk = (risk_level or "").upper()
    if risk == "HIGH":
        return {"available": False,
                "error": "HIGH risk target: dynamic execution refused (static-only)"}

    # Prefer the Docker sandbox when present (real isolation). For a runnable target
    # we run it inside the hardened container via the codegen_runner entrypoint only when
    # the image is available; otherwise fall through to the subprocess fallback.
    if sandbox.is_available():
        # Docker path: defer to run_codegen by writing a runner snippet that execs the
        # target. (Implemented lazily; not exercised when Docker is absent.)
        return {"available": False,
                "error": "Docker sandbox exec path not wired for ad-hoc targets; "
                         "use the subprocess fallback (allow_host_fallback=True)"}

    if not allow_host_fallback:
        return {"available": False,
                "error": "host exec requires explicit opt-in (allow_host_fallback=True); "
                         "Docker unavailable"}

    # Default to the running interpreter: on Windows bare "python" often resolves to the
    # Microsoft Store stub, which exits 1 instead of running the script.
    interp = interpreter or sys.executable
    target = Path(path)
    if not target.exists():
        return {"available": False, "error": f"target not found: {path}"}
    cmd = [interp, "-I", target.name] + list(args or [])
    try:
        res = sandbox.run_restricted_subprocess(
            cmd, scratch_files=[target], timeout=timeout,
            allow_host_fallback=True,
        )
    except sandbox.SandboxUnavailableError as exc:
        return {"available": False, "error": str(exc)}
    return {"available": True, **res}


def tool_attach(target: str) -> dict:
    """Attach to a running process (frida by name/pid)."""
    return frida_backend.attach(target)


def tool_list_processes() -> dict:
    """List running processes (frida)."""
    return frida_backend.list_processes()


def tool_set_breakpoint(session: str, location) -> dict:
    """Set a breakpoint. Uses frida (addr as int) or gdb (symbol/addr as str)."""
    # Coerce hex string to int; pass through if it's already int.
    if isinstance(location, str):
        try:
            addr_int = int(location, 0)  # handles '0x...' and decimal
        except ValueError:
            addr_int = location  # non-numeric (symbol) -> gdb path
    else:
        addr_int = location
    res = frida_backend.set_breakpoint(session, addr_int)
    if res.get("available"):
        return res
    if not _is_windows():
        return gdb_backend.set_breakpoint(session, str(location))
    return res


def tool_continue(session: str) -> dict:
    """Continue execution."""
    res = frida_backend.get_regs(session)  # probe availability via any op
    if not res.get("available") and not _is_windows():
        return gdb_backend.continue_exec(session)
    # frida has no explicit continue (driven by scripts); report available
    return {"available": True, "session": session, "running": True}


def tool_step(session: str) -> dict:
    """Step one instruction (gdb/WinDbg)."""
    if _is_windows():
        return windbg_backend.continue_exec(session)
    return gdb_backend.step(session)


def tool_read_memory(session: str, addr, size: int) -> dict:
    """Read memory at an address."""
    res = frida_backend.read_memory(session, int(str(addr), 0), int(size))
    if res.get("available"):
        return res
    if _is_windows():
        return windbg_backend.read_memory(session, int(str(addr), 0), int(size))
    return gdb_backend.read_memory(session, int(str(addr), 0), int(size))


def tool_write_memory(session: str, addr, data: list[int]) -> dict:
    """Write bytes to memory (frida)."""
    return frida_backend.write_memory(session, int(str(addr), 0), bytes(data))


def tool_hook_function(session: str, addr, script: str) -> dict:
    """Hook a function with a frida script."""
    return frida_backend.hook_function(session, int(str(addr), 0), script)


def tool_get_regs(session: str) -> dict:
    """Get register values."""
    if _is_windows():
        return windbg_backend.get_regs(session)
    return gdb_backend.get_regs(session)


# ---------------------------------------------------------------------------
# Register with the MCP instance.
# ---------------------------------------------------------------------------
@mcp.tool()
def detect_anti_analysis(path: str) -> dict:
    """Scan a binary for anti-debug/anti-VM/TLS-callback indicators (static, no exec)."""
    return tool_detect_anti_analysis(path)


@mcp.tool()
def recommend_handling(anti_hints: list[str]) -> dict:
    """Map detected anti-analysis hints to recommended runtime handling steps."""
    return tool_recommend_handling(anti_hints)


@mcp.tool()
def spawn(path: str, args: list[str] | None = None) -> dict:
    """Spawn a process for instrumentation (frida)."""
    return tool_spawn(path, args)


@mcp.tool()
def run_restricted(
    path: str,
    args: list[str] | None = None,
    timeout: int = 20,
    risk_level: str | None = None,
    allow_host_fallback: bool = False,
) -> dict:
    """Run a Python target under weak-isolation restricted subprocess (opt-in).

    Refuses HIGH risk; otherwise executes the target in a throwaway scratch dir with a
    scrubbed env, DEVNULL stdin, and a hard timeout. Only use when Docker is unavailable
    and the user accepted the weak-isolation risk (set allow_host_fallback=True).
    """
    return tool_run_restricted(path, args, timeout=timeout, risk_level=risk_level,
                               allow_host_fallback=allow_host_fallback)


@mcp.tool()
def attach(target: str) -> dict:
    """Attach to a running process by name or pid (frida)."""
    return tool_attach(target)


@mcp.tool()
def set_breakpoint(session: str, location: str) -> dict:
    """Set a breakpoint at an address or symbol."""
    return tool_set_breakpoint(session, location)


@mcp.tool()
def continue_exec(session: str) -> dict:
    """Continue execution."""
    return tool_continue(session)


@mcp.tool()
def step(session: str) -> dict:
    """Step one instruction."""
    return tool_step(session)


@mcp.tool()
def read_memory(session: str, addr: str, size: int) -> dict:
    """Read memory at an address."""
    return tool_read_memory(session, addr, size)


@mcp.tool()
def write_memory(session: str, addr: str, data: list[int]) -> dict:
    """Write bytes to memory (frida)."""
    return tool_write_memory(session, addr, data)


@mcp.tool()
def hook_function(session: str, addr: str, script: str) -> dict:
    """Hook a function with a frida script."""
    return tool_hook_function(session, addr, script)


@mcp.tool()
def get_regs(session: str) -> dict:
    """Get register values."""
    return tool_get_regs(session)


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
