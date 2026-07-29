"""Tests for the dynamic MCP backends (frida/gdb/windbg) — availability-guarded degrades.

No frida/gdb/windbg is installed here, so every backend must report available=False
clearly and never crash. Tests also assert each backend exposes the expected operation
surface (so the server can route to them when engines ARE installed).
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
from mcp_servers.dynamic import frida_backend, gdb_backend, windbg_backend  # noqa: E402


def _force_unavailable(monkeypatch, modname):
    import builtins
    real = builtins.__import__

    def fake(name, *a, **k):
        if name == modname:
            raise ImportError(f"no {modname}")
        return real(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake)


# ---------------------------------------------------------------------------
# frida backend
# ---------------------------------------------------------------------------
def test_frida_spawn_unavailable(monkeypatch, tmp_path):
    _force_unavailable(monkeypatch, "frida")
    res = frida_backend.spawn(str(tmp_path / "x.exe"), [])
    assert res["available"] is False
    assert "error" in res


def test_frida_list_processes_unavailable(monkeypatch):
    _force_unavailable(monkeypatch, "frida")
    res = frida_backend.list_processes()
    assert res["available"] is False


def test_frida_backend_exposes_operations():
    # Surface check: the backend has the functions the server routes to.
    for op in ("spawn", "attach", "list_processes", "set_breakpoint",
               "hook_function", "read_memory", "write_memory", "get_regs"):
        assert callable(getattr(frida_backend, op))


# ---------------------------------------------------------------------------
# gdb backend
# ---------------------------------------------------------------------------
def test_gdb_start_unavailable(monkeypatch, tmp_path):
    _force_unavailable(monkeypatch, "pygdbmi")
    res = gdb_backend.start(str(tmp_path / "x.elf"))
    assert res["available"] is False


def test_gdb_backend_exposes_operations():
    for op in ("start", "set_breakpoint", "continue_exec", "step",
               "read_memory", "get_regs", "backtrace"):
        assert callable(getattr(gdb_backend, op))


# ---------------------------------------------------------------------------
# windbg backend
# ---------------------------------------------------------------------------
def test_windbg_attach_unavailable(monkeypatch):
    _force_unavailable(monkeypatch, "pykd")
    res = windbg_backend.attach("notepad.exe")
    assert res["available"] is False


def test_windbg_backend_exposes_operations():
    for op in ("attach", "set_breakpoint", "continue_exec", "read_memory", "get_regs"):
        assert callable(getattr(windbg_backend, op))
