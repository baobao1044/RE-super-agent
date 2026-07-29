"""Tests for mcp_servers.dynamic.anti_analysis — anti-debug/anti-VM/anti-analysis detection.

Pure-static pattern detection (runs WITHOUT any dynamic engine). Returns hints that feed
the safety gate and the dynamic specialist's pre-execution handling. Uses synthetic
binaries with embedded markers.
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
from mcp_servers.dynamic import anti_analysis  # noqa: E402


def _write(tmp_path, name, raw):
    p = tmp_path / name
    p.write_bytes(raw)
    return p


def test_clean_binary_no_anti_analysis(tmp_path):
    p = _write(tmp_path, "clean.exe",
               bb.build_pe_header(bits=64, machine=bb.IMAGE_FILE_MACHINE_AMD64))
    res = anti_analysis.detect(p)
    assert res["anti_debug"] == []
    assert res["anti_vm"] == []
    assert res["hints"] == []


def test_detects_anti_debug_apis(tmp_path):
    raw = bb.append_markers(
        bb.build_pe_header(bits=64, machine=bb.IMAGE_FILE_MACHINE_AMD64),
        [b"IsDebuggerPresent", b"CheckRemoteDebuggerPresent", b"OutputDebugStringA"],
    )
    p = _write(tmp_path, "ad.exe", raw)
    res = anti_analysis.detect(p)
    assert "anti_debug" in res["hints"]
    assert "IsDebuggerPresent" in res["anti_debug"]


def test_detects_anti_vm_strings(tmp_path):
    raw = bb.append_markers(
        bb.build_pe_header(bits=64, machine=bb.IMAGE_FILE_MACHINE_AMD64),
        [b"VMware", b"VBoxService", b"\\.\\VBoxGuest"],
    )
    p = _write(tmp_path, "avm.exe", raw)
    res = anti_analysis.detect(p)
    assert "anti_vm" in res["hints"]
    assert "VMware" in res["anti_vm"]


def test_detects_tls_callback_indicator(tmp_path):
    # a PE with a .tls section name suggests TLS callbacks (entry-point traps)
    raw = bb.append_markers(
        bb.build_pe_header(bits=64, machine=bb.IMAGE_FILE_MACHINE_AMD64),
        [b".tls"],
    )
    p = _write(tmp_path, "tls.exe", raw)
    res = anti_analysis.detect(p)
    assert "tls_callback" in res["hints"]


def test_recommends_handling_for_detected_anti_debug(tmp_path):
    p = _write(tmp_path, "clean.exe",
               bb.build_pe_header(bits=64, machine=bb.IMAGE_FILE_MACHINE_AMD64))
    res = anti_analysis.recommend_handling(anti_hints=[])
    # no anti-analysis -> no special handling needed
    assert res["patch_anti_debug"] is False
    assert res["hide_debugger"] is False

    res2 = anti_analysis.recommend_handling(anti_hints=["anti_debug"])
    assert res2["patch_anti_debug"] is True
    assert res2["hide_debugger"] is True

    res3 = anti_analysis.recommend_handling(anti_hints=["anti_vm"])
    assert res3["emulate_clean_environment"] is True
