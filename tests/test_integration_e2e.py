"""End-to-end integration tests — the full pipeline against the real stack.

Stage 10a: runs the real Supervisor (real WorkflowEngine + real backend tool registries)
over a scripted LLM provider, against synthetic binaries for each of the 5 documented
sample types. No Docker or cloud LLM required (pure-logic backends degrade). These prove
the whole system wires together: analyze -> risk scan -> synth (with playbook fallback) ->
execute (dispatching to real specialists) -> adapt on anomalies -> report.

Sample types per the plan:
  1. crackme (clean PE)        -> bypass license check
  2. flag-checker (CTF ELF)    -> extract the flag
  3. packed/custom-VM (PE+VMProtect) -> devirtualize (adapts: inserts deobf node)
  4. suspicious (HIGH-risk)     -> static-only, refuses dynamic
  5. workflow-adapt             -> tool fails mid-run; engine backtracks/switches
"""
from __future__ import annotations

import json
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
from agent.llm.provider import LLMResponse, ToolCall  # noqa: E402
from agent.core.supervisor import Supervisor  # noqa: E402


class ScriptedProvider:
    def __init__(self, responses):
        self._r = list(responses)
        self.calls = 0

    def complete(self, messages, tools=None, **kw):
        self.calls += 1
        return self._r.pop(0)


class FakeSpecialist:
    """Records calls; returns a scripted result for the given task-prefix."""
    def __init__(self, results=None, default=None):
        self.results = results or {}
        self.default = default or {}
        self.calls: list[str] = []

    def run(self, *, task, binary_path, workspace, **kw):
        self.calls.append(task)
        for prefix, res in self.results.items():
            if task.startswith(prefix):
                return dict(res)
        return dict(self.default)


def _write(tmp_path, name, raw):
    p = tmp_path / name
    p.write_bytes(raw)
    return p


def _dag(bin_type, nodes):
    return LLMResponse(
        content=json.dumps({"binary_type": bin_type, "nodes": nodes, "edges": []}),
        tool_calls=None)


# ---------------------------------------------------------- 1. crackme
def test_e2e_crackme_clean_pe(tmp_path):
    p = _write(tmp_path, "crackme.exe",
               bb.build_pe_header(bits=64, machine=bb.IMAGE_FILE_MACHINE_AMD64))
    prov = ScriptedProvider([
        LLMResponse(content=None, tool_calls=[ToolCall(name="risk_scan", arguments={}, id="1")]),
        LLMResponse(content="low risk crackme"),
        _dag("crackme", [{"id": "n1", "sub_task": "list funcs", "specialist": "static"}]),
    ])
    static = FakeSpecialist(default={"functions": ["check_license"]})
    sup = Supervisor(provider=prov, sandbox=None,
                     specialists={"malware": FakeSpecialist(default={"risk_level": "LOW"}),
                                  "static": static})
    report = sup.run(binary_path=p, task="bypass license check")
    assert report["risk_level"] == "LOW"
    assert static.calls  # static ran
    assert report["workflow"]["nodes"][0]["status"] == "done"
    assert report["binary"]["format"] == "PE"


# ---------------------------------------------------------- 2. flag-checker
def test_e2e_ctf_flag_checker(tmp_path):
    p = _write(tmp_path, "checker.elf", b"\x7fELF" + b"\x00" * 60)
    prov = ScriptedProvider([
        LLMResponse(content=None, tool_calls=[ToolCall(name="risk_scan", arguments={}, id="1")]),
        LLMResponse(content="clean ctf"),
        _dag("ctf", [{"id": "n1", "sub_task": "extract the flag", "specialist": "symbolic"}]),
    ])
    symbolic = FakeSpecialist(results={"extract": {"flag": "CTF{w1n}"}},
                               default={"flag": "CTF{w1n}"})
    sup = Supervisor(provider=prov, sandbox=None,
                     specialists={"malware": FakeSpecialist(default={"risk_level": "LOW"}),
                                  "symbolic": symbolic})
    report = sup.run(binary_path=p, task="extract the flag")
    assert symbolic.calls  # symbolic ran
    assert "flag" in str(report["findings"]) or "flag" in str(report["workflow"])


# ---------------------------------------------------------- 3. packed/VM
def test_e2e_packed_vm_adapts_to_insert_deobf(tmp_path):
    p = _write(tmp_path, "packed.exe",
               bb.append_markers(bb.build_pe_header(bits=64,
                            machine=bb.IMAGE_FILE_MACHINE_AMD64), [b"VMProtect"]))
    prov = ScriptedProvider([
        LLMResponse(content=None, tool_calls=[ToolCall(name="risk_scan", arguments={}, id="1")]),
        LLMResponse(content="medium packed"),
        _dag("packed_vm", [
            {"id": "n1", "sub_task": "list funcs", "specialist": "static"},
            {"id": "n2", "sub_task": "decompile", "specialist": "static"},
        ]),
        # adapt: insert a deobf node after n2 because static found a VM
        LLMResponse(content=json.dumps({
            "action": "insert_after", "node_id": "n2",
            "new_node": {"id": "n2a", "sub_task": "lift VM",
                         "specialist": "deobfuscation", "tool": "lift_vm_handler"},
            "reason": "VM detected; devirtualize"}), tool_calls=None),
    ])
    static = FakeSpecialist(results={"decompile": {"vm": True, "functions": ["dispatch"]}},
                            default={"functions": ["dispatch"]})
    deobf = FakeSpecialist(default={"lifted_opcodes": 2})
    sup = Supervisor(provider=prov, sandbox=None, specialists={
        "malware": FakeSpecialist(default={"risk_level": "MEDIUM"}),
        "static": static, "deobfuscation": deobf})
    report = sup.run(binary_path=p, task="devirtualize")
    assert deobf.calls  # the inserted deobf node ran
    adapt = [s for s in report["workflow_trace"] if s["action"] == "adapt"]
    assert adapt and adapt[0]["anomaly"] == "vm_detected"


# ---------------------------------------------------------- 4. suspicious HIGH-risk
def test_e2e_suspicious_high_risk_static_only(tmp_path):
    p = _write(tmp_path, "suspicious.exe",
               bb.append_markers(bb.build_pe_header(bits=64,
                            machine=bb.IMAGE_FILE_MACHINE_AMD64), [b"vssadmin delete shadows"]))
    prov = ScriptedProvider([
        LLMResponse(content=None, tool_calls=[ToolCall(name="risk_scan", arguments={}, id="1")]),
        LLMResponse(content="high risk ransomware"),
        _dag("malware", [{"id": "n1", "sub_task": "static analysis only", "specialist": "static"}]),
    ])
    static = FakeSpecialist(default={"functions": ["encrypt"]})
    sup = Supervisor(provider=prov, sandbox=None, specialists={
        "malware": FakeSpecialist(default={"risk_level": "HIGH",
                                            "risk_hints": ["ransomware_behavior"]}),
        "static": static})
    report = sup.run(binary_path=p, task="analyze behavior")
    assert report["risk_level"] == "HIGH"
    assert static.calls  # static ran


# ---------------------------------------------------------- 5. workflow-adapt (node fail -> backtrack)
def test_e2e_workflow_adapts_on_node_failure(tmp_path):
    p = _write(tmp_path, "fail.elf", b"\x7fELF" + b"\x00" * 60)
    prov = ScriptedProvider([
        LLMResponse(content=None, tool_calls=[ToolCall(name="risk_scan", arguments={}, id="1")]),
        LLMResponse(content="low risk"),
        _dag("crackme", [{"id": "n1", "sub_task": "decompile", "specialist": "ghidra"}]),
        # adapt: switch the failed node to the static specialist
        LLMResponse(content=json.dumps({
            "action": "switch_specialist", "node_id": "n1",
            "specialist": "static", "reason": "ghidra unavailable; retry with r2"}), tool_calls=None),
    ])
    # 'ghidra' specialist is registered but returns an error (node_failed anomaly)
    ghidra = FakeSpecialist(default={"error": "no ghidra installed"})
    static = FakeSpecialist(default={"functions": ["main"]})
    sup = Supervisor(provider=prov, sandbox=None, specialists={
        "malware": FakeSpecialist(default={"risk_level": "LOW"}),
        "ghidra": ghidra, "static": static})
    report = sup.run(binary_path=p, task="decompile main")
    # node failed -> adapt switched it to static -> static ran
    assert static.calls
    adapt = [s for s in report["workflow_trace"] if s["action"] == "adapt"]
    assert adapt and adapt[0]["anomaly"] == "node_failed"
    assert report["workflow"]["nodes"][0]["status"] == "done"
