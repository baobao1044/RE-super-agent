"""Tests for mcp_servers.dynamic.server — the FastMCP dynamic tool layer.

Tools route across backends (frida primary, gdb Linux, windbg Windows) and include the
anti-analysis cluster (detect / patch / hide / emulate) which is pure-static and always
available. Tests call server.tool_* directly.
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
from mcp_servers.dynamic import server  # noqa: E402


def _write(tmp_path, name, raw):
    p = tmp_path / name
    p.write_bytes(raw)
    return p


def test_detect_anti_analysis_pure_static(tmp_path):
    raw = bb.append_markers(
        bb.build_pe_header(bits=64, machine=bb.IMAGE_FILE_MACHINE_AMD64),
        [b"IsDebuggerPresent", b"VMware"],
    )
    p = _write(tmp_path, "ad.exe", raw)
    res = server.tool_detect_anti_analysis(str(p))
    assert "anti_debug" in res["hints"]
    assert "anti_vm" in res["hints"]


def test_recommend_handling_returns_steps():
    res = server.tool_recommend_handling(anti_hints=["anti_debug", "anti_vm"])
    assert res["patch_anti_debug"] is True
    assert res["hide_debugger"] is True
    assert res["emulate_clean_environment"] is True


def test_spawn_unavailable_without_frida(tmp_path):
    p = _write(tmp_path, "x.exe",
               bb.build_pe_header(bits=64, machine=bb.IMAGE_FILE_MACHINE_AMD64))
    res = server.tool_spawn(str(p), [])
    assert res.get("available") is False


def test_list_processes_unavailable_without_frida():
    res = server.tool_list_processes()
    assert res.get("available") is False


def test_attach_unavailable_without_frida():
    res = server.tool_attach("notepad.exe")
    assert res.get("available") is False


def test_set_breakpoint_unavailable_without_engine():
    res = server.tool_set_breakpoint("any", "0x401000")
    assert res.get("available") is False


def test_read_memory_unavailable_without_engine():
    res = server.tool_read_memory("any", "0x401000", 16)
    assert res.get("available") is False


def test_server_has_mcp_and_tools():
    assert hasattr(server, "mcp")
    for name in ("tool_spawn", "tool_attach", "tool_list_processes",
                 "tool_set_breakpoint", "tool_continue", "tool_step",
                 "tool_read_memory", "tool_write_memory", "tool_hook_function",
                 "tool_get_regs", "tool_detect_anti_analysis",
                 "tool_recommend_handling", "tool_patch_anti_debug",
                 "tool_hide_debugger", "tool_emulate_clean_environment"):
        assert callable(getattr(server, name))


# ---------------------------------------------------------------------------
# run_restricted: weak-isolation exec of a (Python) target, opt-in only
# ---------------------------------------------------------------------------
def _write_py(tmp_path, name, body):
    import textwrap
    p = tmp_path / name
    p.write_text(textwrap.dedent(body))
    return p


def test_run_restricted_runs_benign_python(tmp_path):
    p = _write_py(tmp_path, "hello.py", "print('DYNAMIC_OUT')")
    res = server.tool_run_restricted(str(p), timeout=15, allow_host_fallback=True)
    assert res["available"] is True
    assert res["ok"] is True
    assert "DYNAMIC_OUT" in res["stdout"]


def test_run_restricted_refuses_high_risk(tmp_path):
    p = _write_py(tmp_path, "hi.py", "print('x')")
    res = server.tool_run_restricted(str(p), risk_level="HIGH", allow_host_fallback=True)
    assert res["available"] is False
    assert "HIGH" in res.get("error", "") or "high" in res.get("error", "").lower()


def test_run_restricted_requires_opt_in(tmp_path):
    p = _write_py(tmp_path, "hi.py", "print('x')")
    res = server.tool_run_restricted(str(p), timeout=15)
    assert res["available"] is False
    assert "opt-in" in res.get("error", "").lower() or "fallback" in res.get("error", "").lower()


def test_run_restricted_timeout(tmp_path):
    p = _write_py(tmp_path, "sleep.py", "import time; print('S', flush=True); time.sleep(30); print('E')")
    res = server.tool_run_restricted(str(p), timeout=2, allow_host_fallback=True)
    assert res["available"] is True
    assert res["timed_out"] is True
    assert res["ok"] is False


def test_run_restricted_captures_stderr_and_exit(tmp_path):
    p = _write_py(tmp_path, "fail.py", "import sys; sys.stderr.write('BOOM'); sys.exit(4)")
    res = server.tool_run_restricted(str(p), timeout=15, allow_host_fallback=True)
    assert res["available"] is True
    assert res["ok"] is False
    assert res["exit_code"] == 4
    assert "BOOM" in res["stderr"]
