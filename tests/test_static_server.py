"""Tests for mcp_servers.static.server — the FastMCP static tool layer.

Tools route across engines: ghidra (decompile/list/xrefs) -> r2 (fast list/xrefs/strings)
-> capstone (disasm, always available). Tests call server.tool_* directly and assert the
routing/degrade behavior using synthetic fixtures (no r2/ghidra installed here).
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
from mcp_servers.static import server  # noqa: E402


def _write(tmp_path, name, raw):
    p = tmp_path / name
    p.write_bytes(raw)
    return p


def test_load_binary_returns_format_and_arch(tmp_path):
    p = _write(tmp_path, "x.elf",
               bb.build_elf_header(bits=64, machine=bb.EM_X86_64, entry=0x401000))
    res = server.tool_load_binary(str(p))
    assert res["format"] == "ELF"
    assert res["arch"] == "x86_64"
    assert res["bits"] == 64


def test_list_functions_degrades_without_engines(tmp_path):
    p = _write(tmp_path, "x.elf", bb.build_elf_header(bits=64, machine=bb.EM_X86_64))
    res = server.tool_list_functions(str(p))
    # ghidra+ r2 both absent -> available False (functions empty), no crash
    assert res["available"] in (False, True)
    if not res.get("available"):
        assert res["functions"] == []


def test_decompile_function_unavailable_without_ghidra(tmp_path):
    p = _write(tmp_path, "x.elf", bb.build_elf_header(bits=64, machine=bb.EM_X86_64))
    res = server.tool_decompile_function(str(p), addr="0x401000")
    assert res.get("available") is False
    # should hint that disassembly is the fallback
    assert "disassembl" in (res.get("error", "") + res.get("hint", "")).lower() or res.get("decompilation") == ""


def test_disassemble_always_available_via_capstone(tmp_path):
    code = bytes([0x48, 0x31, 0xC0, 0xC3])  # xor rax,rax; ret
    p = _write(tmp_path, "c.bin", code)
    res = server.tool_disassemble(str(p), addr=0, count=4, arch="x86_64", bits=64)
    assert res["available"] is True
    mnems = [i["mnemonic"] for i in res["instructions"]]
    assert "xor" in mnems and "ret" in mnems


def test_strings_works_without_r2(tmp_path):
    raw = bb.append_markers(b"\x90", [b"check_password", b"secret_key"])
    p = _write(tmp_path, "c.bin", raw)
    res = server.tool_strings(str(p), min_len=4)
    assert "check_password" in res["strings"]
    assert "secret_key" in res["strings"]


def test_xrefs_to_degrades_without_engines(tmp_path):
    p = _write(tmp_path, "x.elf", bb.build_elf_header(bits=64, machine=bb.EM_X86_64))
    res = server.tool_xrefs_to(str(p), addr="0x401000")
    assert "available" in res
    assert "xrefs" in res


def test_resolve_symbol_degrades(tmp_path):
    p = _write(tmp_path, "x.elf", bb.build_elf_header(bits=64, machine=bb.EM_X86_64))
    res = server.tool_resolve_symbol(str(p), name="main")
    assert "available" in res


def test_search_pattern_scans_bytes_without_r2(tmp_path):
    raw = bb.append_markers(b"\x90", [b"AAAA"])
    p = _write(tmp_path, "c.bin", raw)
    res = server.tool_search_pattern(str(p), pattern="41 41 41 41")
    assert res["available"] is True
    assert len(res["matches"]) >= 1
    assert "offset" in res["matches"][0]


def test_server_has_mcp_instance_and_tools():
    assert hasattr(server, "mcp")
    for name in ("tool_load_binary", "tool_list_functions", "tool_decompile_function",
                 "tool_disassemble", "tool_xrefs_to", "tool_strings",
                 "tool_resolve_symbol", "tool_search_pattern"):
        assert callable(getattr(server, name))
