"""Tests for the static MCP backends.

r2 and Ghidra are NOT installed in this environment, so r2_backend must degrade
gracefully (available=False) AND fall back to capstone (always installed) for raw
disassembly. Ghidra backend degrades to available=False. Tests use synthetic ELF/PE
fixtures with embedded code-ish bytes for capstone disasm.
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
from mcp_servers.static import r2_backend, ghidra_backend  # noqa: E402


def _write(tmp_path, name, raw):
    p = tmp_path / name
    p.write_bytes(raw)
    return p


# ---------------------------------------------------------------------------
# r2 backend availability
# ---------------------------------------------------------------------------
def test_r2_unavailable_returns_status(tmp_path, monkeypatch):
    # Force r2pipe / r2 to be unavailable.
    import builtins
    real = builtins.__import__

    def fake(name, *a, **k):
        if name == "r2pipe":
            raise ImportError("no r2pipe")
        return real(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake)
    p = _write(tmp_path, "x.elf", bb.build_elf_header(bits=64, machine=bb.EM_X86_64))
    res = r2_backend.list_functions(p)
    # r2 missing -> degrade, but should NOT crash; capstone fallback doesn't list funcs
    assert res["available"] is False or "engine" in res.get("error", "")


# ---------------------------------------------------------------------------
# capstone fallback disassembly (no r2 needed)
# ---------------------------------------------------------------------------
def test_disassemble_with_capstone_x64(tmp_path):
    # x86-64: 48 31 c0 = xor rax,rax ; c3 = ret
    code = bytes([0x48, 0x31, 0xC0, 0xC3])
    p = _write(tmp_path, "c.bin", code)
    res = r2_backend.disassemble(p, addr=0, count=4, arch="x86_64", bits=64)
    assert res["available"] is True  # capstone fallback makes disasm always available
    mnems = [i["mnemonic"] for i in res["instructions"]]
    assert "xor" in mnems
    assert "ret" in mnems


def test_disassemble_x86_32(tmp_path):
    # x86: 33 c0 = xor eax,eax ; c3 = ret
    code = bytes([0x33, 0xC0, 0xC3])
    p = _write(tmp_path, "c.bin", code)
    res = r2_backend.disassemble(p, addr=0, count=4, arch="x86", bits=32)
    assert res["available"] is True
    mnems = [i["mnemonic"] for i in res["instructions"]]
    assert "xor" in mnems and "ret" in mnems


def test_disassemble_records_addr_and_bytes(tmp_path):
    code = bytes([0x90, 0xC3])  # nop ; ret
    p = _write(tmp_path, "c.bin", code)
    # addr=0x401000 is the virtual address reported; file_offset=0 reads from file start
    res = r2_backend.disassemble(p, addr=0x401000, count=4, arch="x86_64", bits=64, file_offset=0)
    first = res["instructions"][0]
    assert first["addr"] == 0x401000
    assert first["bytes"] == "90"
    assert first["mnemonic"] == "nop"


def test_disassemble_unknown_arch_falls_back_no_crash(tmp_path):
    p = _write(tmp_path, "c.bin", b"\x00\x00")
    res = r2_backend.disassemble(p, addr=0, count=4, arch="bogus", bits=64)
    assert res["available"] is True  # capstone didn't crash; empty instructions
    assert res["instructions"] == []


def test_strings_via_r2_backend_falls_back_to_strings_backend(tmp_path):
    raw = bb.append_markers(b"\x90\xc3", [b"check_password", b"secret"])
    p = _write(tmp_path, "c.bin", raw)
    res = r2_backend.strings(p, min_len=4)
    assert "check_password" in res["strings"]


# ---------------------------------------------------------------------------
# ghidra backend degrades
# ---------------------------------------------------------------------------
def test_ghidra_decompile_unavailable(tmp_path, monkeypatch):
    import builtins
    real = builtins.__import__

    def fake(name, *a, **k):
        if name == "pyghidra" or name.startswith("ghidra"):
            raise ImportError("no ghidra")
        return real(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake)
    p = _write(tmp_path, "x.elf", bb.build_elf_header(bits=64, machine=bb.EM_X86_64))
    res = ghidra_backend.decompile_function(p, addr=0x401000)
    assert res["available"] is False
    assert "error" in res


def test_ghidra_list_functions_unavailable(tmp_path, monkeypatch):
    import builtins
    real = builtins.__import__

    def fake(name, *a, **k):
        if name == "pyghidra" or name.startswith("ghidra"):
            raise ImportError("no ghidra")
        return real(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake)
    p = _write(tmp_path, "x.elf", bb.build_elf_header(bits=64, machine=bb.EM_X86_64))
    res = ghidra_backend.list_functions(p)
    assert res["available"] is False
