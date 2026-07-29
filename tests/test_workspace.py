"""Tests for agent.state.workspace — the shared RE workspace state.

The workspace is the cross-tool shared state specialists write to and the supervisor
reads from: binary meta, discovered functions, findings, hypotheses, cross-tool
references (static addr -> dynamic hook -> VM spec), and the workflow trace.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.binary import BinaryInfo  # noqa: E402
from agent.state.workspace import Workspace  # noqa: E402


def _bininfo() -> BinaryInfo:
    return BinaryInfo(
        path="crackme.exe", format="PE", arch="x86_64", bits=64, endian="little",
        entry=0x1000, sha256="b" * 64, size=4096, risk_hints=[],
    )


def test_set_binary_stores_meta_and_risk():
    ws = Workspace(session_id="s1")
    ws.set_binary(_bininfo(), risk_level="LOW")
    assert ws.binary["format"] == "PE"
    assert ws.binary["arch"] == "x86_64"
    assert ws.binary["sha256"] == "b" * 64
    assert ws.binary["risk_level"] == "LOW"


def test_add_and_get_function_by_int_addr():
    ws = Workspace(session_id="s1")
    ws.add_function(addr=0x401234, name="check_pw", notes="license check", source="static")
    fn = ws.get_function(0x401234)
    assert fn is not None
    assert fn["name"] == "check_pw"
    assert fn["notes"] == "license check"
    assert fn["source"] == "static"


def test_get_function_missing_returns_none():
    ws = Workspace(session_id="s1")
    assert ws.get_function(0xdeadbeef) is None


def test_add_function_updates_notes_if_exists():
    ws = Workspace(session_id="s1")
    ws.add_function(addr=0x10, name="f", source="static")
    ws.add_function(addr=0x10, name="f", notes="renamed by deobf", source="deobfuscation")
    fn = ws.get_function(0x10)
    assert fn["notes"] == "renamed by deobf"


def test_add_finding_assigns_id_and_stores():
    ws = Workspace(session_id="s1")
    fid = ws.add_finding(kind="license_check", summary="cmp at 0x401234", source="static")
    assert fid == 1
    assert ws.findings[0]["summary"] == "cmp at 0x401234"
    fid2 = ws.add_finding(kind="flag", summary="flag found", source="symbolic")
    assert fid2 == 2


def test_add_hypothesis_with_status():
    ws = Workspace(session_id="s1")
    hid = ws.add_hypothesis("patch the comparison to always pass")
    assert hid == 1
    assert ws.hypotheses[0]["status"] == "open"


def test_resolve_hypothesis():
    ws = Workspace(session_id="s1")
    hid = ws.add_hypothesis("guess")
    ws.resolve_hypothesis(hid, status="confirmed", evidence="dynamic confirmed bypass")
    assert ws.hypotheses[0]["status"] == "confirmed"
    assert "dynamic confirmed bypass" in ws.hypotheses[0]["evidence"]


def test_add_cross_ref_links_static_to_dynamic():
    ws = Workspace(session_id="s1")
    ws.add_cross_ref(static_addr=0x401234, dynamic_hook="hook_check_pw", kind="function")
    ref = ws.cross_refs[0]
    assert ref["static_addr"] == 0x401234
    assert ref["dynamic_hook"] == "hook_check_pw"
    assert ref["kind"] == "function"


def test_set_vm_spec_for_deobf():
    ws = Workspace(session_id="s1")
    ws.set_vm_spec({"dispatch": 0x402000, "opcodes": {"0x01": "vm_add"}})
    assert ws.vm_spec["opcodes"]["0x01"] == "vm_add"


def test_record_workflow_step_appends_trace():
    ws = Workspace(session_id="s1")
    ws.record_workflow_step(action="adapt", reason="symbolic path explosion; inserting trace node")
    assert ws.workflow_trace[-1]["action"] == "adapt"
    assert "path explosion" in ws.workflow_trace[-1]["reason"]


def test_save_and_load_roundtrip(tmp_path):
    ws = Workspace(session_id="s1")
    ws.set_binary(_bininfo(), risk_level="MEDIUM")
    ws.add_function(addr=0x401234, name="check_pw", source="static")
    ws.add_finding(kind="license", summary="x", source="static")
    ws.add_cross_ref(static_addr=0x401234, dynamic_hook="h", kind="function")
    ws.record_workflow_step(action="init", reason="start")
    p = tmp_path / "ws.json"
    ws.save(p)

    ws2 = Workspace.load(p)
    assert ws2.session_id == "s1"
    assert ws2.binary["arch"] == "x86_64"
    assert ws2.get_function(0x401234)["name"] == "check_pw"
    assert ws2.findings[0]["kind"] == "license"
    assert ws2.cross_refs[0]["static_addr"] == 0x401234
    assert ws2.workflow_trace[-1]["action"] == "init"


def test_checkpoint_returns_dag_version(tmp_path):
    ws = Workspace(session_id="s1")
    ws.record_workflow_step(action="init", reason="v1")
    ver = ws.checkpoint()
    ws.record_workflow_step(action="adapt", reason="v2")
    # checkpoint should capture an immutable copy at that moment
    snap = ws.checkpoints[ver]
    assert len(snap["workflow_trace"]) == 1  # only the init step, before adapt
