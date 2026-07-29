"""Tests for mcp_servers.malware.risk_policy — cheap heuristic risk scan.

These tests embed recognizable markers (strings/section names) into synthetic binaries and
assert the heuristic scan classifies them correctly, feeding the safety gate. The scan must
run with NO external engine installed (pure byte/string heuristics), with YARA optional.
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
from tools.binary import analyze  # noqa: E402
from mcp_servers.malware import risk_policy  # noqa: E402


def _scan(tmp_path, name, raw, **kw):
    p = tmp_path / name
    p.write_bytes(raw)
    info = analyze(p, **kw) if "analyze" in dir(analyze) else None
    return info, p


# ---------------------------------------------------------------------------
# clean binary -> LOW
# ---------------------------------------------------------------------------
def test_clean_pe_is_low(tmp_path):
    raw = bb.build_pe_header(bits=64, machine=bb.IMAGE_FILE_MACHINE_AMD64)
    p = tmp_path / "clean.exe"
    p.write_bytes(raw)
    info = analyze(p)
    ra = risk_policy.risk_scan(info, data=p.read_bytes())
    assert ra.risk_level == "LOW"
    assert "is_dll" not in ra.risk_hints


def test_dll_flagged_medium(tmp_path):
    raw = bb.build_pe_header(bits=64, machine=bb.IMAGE_FILE_MACHINE_AMD64, is_dll=True)
    p = tmp_path / "lib.dll"
    p.write_bytes(raw)
    info = analyze(p)
    ra = risk_policy.risk_scan(info, data=p.read_bytes())
    assert ra.risk_level == "MEDIUM"
    assert "is_dll" in ra.risk_hints


# ---------------------------------------------------------------------------
# packer detection
# ---------------------------------------------------------------------------
def test_upx_packer_detected(tmp_path):
    raw = bb.append_markers(
        bb.build_pe_header(bits=64, machine=bb.IMAGE_FILE_MACHINE_AMD64),
        [b"UPX0", b"UPX1"],
    )
    p = tmp_path / "packed.exe"
    p.write_bytes(raw)
    info = analyze(p)
    ra = risk_policy.risk_scan(info, data=p.read_bytes())
    assert "packer" in ra.risk_hints
    assert ra.risk_level == "MEDIUM"


# ---------------------------------------------------------------------------
# anti-debug detection
# ---------------------------------------------------------------------------
def test_anti_debug_strings_detected(tmp_path):
    raw = bb.append_markers(
        bb.build_pe_header(bits=64, machine=bb.IMAGE_FILE_MACHINE_AMD64),
        [b"IsDebuggerPresent", b"CheckRemoteDebuggerPresent"],
    )
    p = tmp_path / "ad.exe"
    p.write_bytes(raw)
    info = analyze(p)
    ra = risk_policy.risk_scan(info, data=p.read_bytes())
    assert "anti_debug" in ra.risk_hints
    assert ra.risk_level == "MEDIUM"


# ---------------------------------------------------------------------------
# anti-vm detection
# ---------------------------------------------------------------------------
def test_anti_vm_strings_detected(tmp_path):
    raw = bb.append_markers(
        bb.build_pe_header(bits=64, machine=bb.IMAGE_FILE_MACHINE_AMD64),
        [b"VMware", b"VirtualBox", b"VBoxService"],
    )
    p = tmp_path / "avm.exe"
    p.write_bytes(raw)
    info = analyze(p)
    ra = risk_policy.risk_scan(info, data=p.read_bytes())
    assert "anti_vm" in ra.risk_hints
    assert ra.risk_level == "MEDIUM"


# ---------------------------------------------------------------------------
# kernel driver detection (filename .sys -> HIGH)
# ---------------------------------------------------------------------------
def test_kernel_driver_by_sys_extension_high(tmp_path):
    raw = bb.build_pe_header(bits=64, machine=bb.IMAGE_FILE_MACHINE_AMD64)
    p = tmp_path / "evil.sys"
    p.write_bytes(raw)
    info = analyze(p)
    ra = risk_policy.risk_scan(info, data=p.read_bytes())
    assert "kernel_driver" in ra.risk_hints
    assert ra.risk_level == "HIGH"


# ---------------------------------------------------------------------------
# wiper / ransomware signatures -> HIGH
# ---------------------------------------------------------------------------
def test_wiper_signature_high(tmp_path):
    raw = bb.append_markers(
        bb.build_pe_header(bits=64, machine=bb.IMAGE_FILE_MACHINE_AMD64),
        [b"vssadmin delete shadows", b"bcdedit /default"],
    )
    p = tmp_path / "wiper.exe"
    p.write_bytes(raw)
    info = analyze(p)
    ra = risk_policy.risk_scan(info, data=p.read_bytes())
    assert "wiper_signature" in ra.risk_hints or "ransomware_behavior" in ra.risk_hints
    assert ra.risk_level == "HIGH"


# ---------------------------------------------------------------------------
# environment recommendation
# ---------------------------------------------------------------------------
def test_recommend_environment_returns_dict(tmp_path):
    raw = bb.build_pe_header(bits=64, machine=bb.IMAGE_FILE_MACHINE_AMD64)
    p = tmp_path / "c.exe"
    p.write_bytes(raw)
    info = analyze(p)
    ra = risk_policy.risk_scan(info, data=p.read_bytes())
    rec = ra.recommendation
    assert "mode" in rec and "reason" in rec
    # LOW -> sandbox mode recommended
    assert rec["mode"] in ("sandbox", "static_only", "qiling_first")


def test_high_risk_recommendation_is_static_only(tmp_path):
    raw = bb.build_pe_header(bits=64, machine=bb.IMAGE_FILE_MACHINE_AMD64)
    p = tmp_path / "evil.sys"
    p.write_bytes(raw)
    info = analyze(p)
    ra = risk_policy.risk_scan(info, data=p.read_bytes())
    assert ra.recommendation["mode"] == "static_only"


# ---------------------------------------------------------------------------
# YARA optional: scan with no engine still works; with rules adds hints
# ---------------------------------------------------------------------------
def test_scan_without_yara_engine_still_returns_level(tmp_path):
    raw = bb.build_pe_header(bits=64, machine=bb.IMAGE_FILE_MACHINE_AMD64)
    p = tmp_path / "c.exe"
    p.write_bytes(raw)
    info = analyze(p)
    # yara not installed in test env -> must not crash
    ra = risk_policy.risk_scan(info, data=p.read_bytes())
    assert ra.risk_level in ("LOW", "MEDIUM", "HIGH")


def test_scan_with_yara_rule_matches_adds_hint(tmp_path, monkeypatch):
    raw = bb.append_markers(
        bb.build_pe_header(bits=64, machine=bb.IMAGE_FILE_MACHINE_AMD64),
        [b"SUPER_SECRET_MARKER_XYZ"],
    )
    p = tmp_path / "c.exe"
    p.write_bytes(raw)
    info = analyze(p)
    rule_src = (
        'rule test_marker { strings: $a = "SUPER_SECRET_MARKER_XYZ" '
        'condition: $a }'
    )
    # Inject a fake yara module so the scan path runs without the real engine.
    import types

    fake_yara = types.ModuleType("yara")

    class _Compiled:
        def match(self, data):
            return ["test_marker"] if b"SUPER_SECRET_MARKER_XYZ" in data else []

    def _compile(source=""):
        return _Compiled()

    fake_yara.compile = _compile
    fake_yara.YaraError = Exception
    monkeypatch.setitem(sys.modules, "yara", fake_yara)

    ra = risk_policy.risk_scan(info, data=p.read_bytes(), yara_rules=[rule_src])
    assert "yara:test_marker" in ra.risk_hints


def test_scan_with_yara_rule_error_is_swalllowed(tmp_path, monkeypatch):
    raw = bb.build_pe_header(bits=64, machine=bb.IMAGE_FILE_MACHINE_AMD64)
    p = tmp_path / "c.exe"
    p.write_bytes(raw)
    info = analyze(p)
    rule_src = "rule bad { bad syntax"
    import types

    fake_yara = types.ModuleType("yara")

    def _compile(source=""):
        raise Exception("compile failed")

    fake_yara.compile = _compile
    fake_yara.YaraError = Exception
    monkeypatch.setitem(sys.modules, "yara", fake_yara)

    ra = risk_policy.risk_scan(info, data=p.read_bytes(), yara_rules=[rule_src])
    # error must not crash; yara hints empty
    assert all(not h.startswith("yara:") for h in ra.risk_hints)
    assert any("yara_error" in r for r in ra.reasons)
