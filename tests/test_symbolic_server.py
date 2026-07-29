"""Tests for mcp_servers.symbolic.server — the FastMCP symbolic tool layer.

Tools: load_project / explore_to / find_input_satisfying / extract_flag / get_state_info.
The pure-solver-backed tools are always available; angr-backed ones degrade.
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
from mcp_servers.symbolic import server  # noqa: E402


def _write(tmp_path, name, raw):
    p = tmp_path / name
    p.write_bytes(raw)
    return p


def test_load_project_degrades_without_angr(tmp_path):
    p = _write(tmp_path, "x.elf", bb.build_elf_header(bits=64, machine=bb.EM_X86_64))
    res = server.tool_load_project(str(p))
    assert res.get("available") is False


def test_explore_to_degrades(tmp_path):
    p = _write(tmp_path, "x.elf", bb.build_elf_header(bits=64, machine=bb.EM_X86_64))
    res = server.tool_explore_to(str(p), target_addr=0x401000)
    assert "available" in res


def test_find_input_satisfying_pure_solver(tmp_path):
    """Server exposes a pure-solver find_input satisfying a predicate."""
    res = server.tool_find_input_satisfying(
        predicate_str="lambda x: x == bytes([7])",
        input_length=1, alphabet_start=0, alphabet_end=16)
    assert res["found"] is True
    assert res["input"] == [7]


def test_extract_flag_pure_solver(tmp_path):
    res = server.tool_extract_flag(
        predicate_str="lambda x: x == b'CAT'",
        expected_len=3, alphabet_start=65, alphabet_end=91)
    assert res["found"] is True
    assert res["flag"] == "CAT"


def test_get_state_info_degrades(tmp_path):
    p = _write(tmp_path, "x.elf", bb.build_elf_header(bits=64, machine=bb.EM_X86_64))
    res = server.tool_get_state_info(str(p))
    assert "available" in res


def test_server_has_mcp_and_tools():
    assert hasattr(server, "mcp")
    for name in ("tool_load_project", "tool_explore_to", "tool_find_input_satisfying",
                 "tool_extract_flag", "tool_get_state_info"):
        assert callable(getattr(server, name))
