"""Symbolic MCP server (FastMCP).

Exposes the symbolic-analysis tool layer: angr-backed load/explore/state-info (degrade
when angr missing) + pure-Python find_input_satisfying / extract_flag (always available).
Predicates are passed as source strings and evaluated in a restricted namespace.

Run as a stdio MCP server:  python -m mcp_servers.symbolic.server
"""
from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from mcp_servers.symbolic import angr_backend

mcp = FastMCP("re-symbolic")

# Restricted namespace for predicate evaluation (no builtins).
_EVAL_NAMESPACE = {"bytes": bytes, "len": len, "ord": ord, "chr": chr,
                   "range": range, "list": list}


def _compile_predicate(predicate_str: str):
    """Compile a lambda string like 'lambda x: x == bytes([7])' safely."""
    if not (predicate_str.strip().startswith("lambda")):
        raise ValueError("predicate must be a lambda expression")
    code = eval(predicate_str, dict(_EVAL_NAMESPACE), {})  # noqa: S307 — restricted ns
    return code


# ---------------------------------------------------------------------------
def tool_load_project(path: str) -> dict:
    return angr_backend.load_project(path)


def tool_explore_to(path: str, target_addr: int, avoid: list[int] | None = None) -> dict:
    return angr_backend.explore_to(path, target_addr, avoid=avoid)


def tool_find_input_satisfying(predicate_str: str, input_length: int,
                               alphabet_start: int = 0, alphabet_end: int = 256) -> dict:
    pred = _compile_predicate(predicate_str)
    return angr_backend.find_input_satisfying(
        predicate=pred, input_length=input_length,
        alphabet=range(alphabet_start, alphabet_end), use_angr=True)


def tool_extract_flag(predicate_str: str, expected_len: int,
                      alphabet_start: int = 32, alphabet_end: int = 127) -> dict:
    pred = _compile_predicate(predicate_str)
    return angr_backend.extract_flag(
        flag_predicate=pred, expected_len=expected_len,
        alphabet=range(alphabet_start, alphabet_end), use_angr=True)


def tool_get_state_info(path: str) -> dict:
    return angr_backend.get_state_info(path)


# ---------------------------------------------------------------------------
@mcp.tool()
def load_project(path: str) -> dict:
    """Load a binary into angr for symbolic analysis (degrades if angr missing)."""
    return tool_load_project(path)


@mcp.tool()
def explore_to(path: str, target_addr: int, avoid: list[int] | None = None) -> dict:
    """Symbolically explore execution paths to a target address."""
    return tool_explore_to(path, target_addr, avoid)


@mcp.tool()
def find_input_satisfying(predicate_str: str, input_length: int,
                          alphabet_start: int = 0, alphabet_end: int = 256) -> dict:
    """Find an input satisfying a lambda predicate (pure solver fallback)."""
    return tool_find_input_satisfying(predicate_str, input_length, alphabet_start, alphabet_end)


@mcp.tool()
def extract_flag(predicate_str: str, expected_len: int,
                 alphabet_start: int = 32, alphabet_end: int = 127) -> dict:
    """Find bytes of expected_len satisfying a flag predicate; return as a flag string."""
    return tool_extract_flag(predicate_str, expected_len, alphabet_start, alphabet_end)


@mcp.tool()
def get_state_info(path: str) -> dict:
    """Get symbolic state info (CFG function count, entry) via angr."""
    return tool_get_state_info(path)


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
