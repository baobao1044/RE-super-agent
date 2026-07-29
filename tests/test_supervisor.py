"""Tests for agent.core.supervisor — the top-level orchestrator.

Stage 9a: the Supervisor drives the full pipeline: analyze the binary -> run a malware risk
scan -> synthesize the workflow DAG (with a bundled playbook as fallback) -> execute it,
dispatching nodes to specialists, adapting on anomalies -> synthesize a final report from
the workspace. Specialists and the LLM provider are injectable so the test needs no Docker
or cloud LLM.
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
from agent.llm.provider import LLMResponse, ToolCall  # noqa: E402
from agent.state.workspace import Workspace  # noqa: E402
from agent.core.supervisor import Supervisor  # noqa: E402


class ScriptedProvider:
    def __init__(self, responses):
        self._r = list(responses)
        self.calls = 0

    def complete(self, messages, tools=None, **kw):
        self.calls += 1
        return self._r.pop(0)


class FakeSpecialist:
    """A stand-in specialist that records calls and returns a fixed result."""
    def __init__(self, result: dict):
        self.result = result
        self.calls: list[dict] = []

    def run(self, *, task, binary_path, workspace, **kw):
        self.calls.append({"task": task, "binary_path": str(binary_path)})
        return dict(self.result)


def _write(tmp_path, name, raw):
    p = tmp_path / name
    p.write_bytes(raw)
    return p


# --------------------------------------------------------------------------- report
def test_supervisor_returns_report_with_binary_meta(tmp_path):
    p = _write(tmp_path, "x.exe",
               bb.build_pe_header(bits=64, machine=bb.IMAGE_FILE_MACHINE_AMD64))
    prov = ScriptedProvider([
        # 1. malware risk_scan ReAct step (call risk_scan)
        LLMResponse(content=None, tool_calls=[ToolCall(name="risk_scan", arguments={}, id="1")]),
        # 2. malware risk_scan final text
        LLMResponse(content="Low-risk crackme."),
        # 3. workflow synthesis DAG JSON
        LLMResponse(content='{"binary_type":"crackme","nodes":['
                           '{"id":"n1","sub_task":"scan","specialist":"malware"}],"edges":[]}',
                     tool_calls=None),
    ])
    specialists = {
        "malware": FakeSpecialist({"risk_level": "LOW"}),
        "static": FakeSpecialist({"functions": ["main"]}),
    }
    sup = Supervisor(provider=prov, sandbox=None, specialists=specialists)
    report = sup.run(binary_path=p, task="bypass license check")
    assert report["binary"]["format"] == "PE"
    assert report["binary"]["arch"] in ("x86_64", "amd64")
    assert report["risk_level"] == "LOW"
    assert "summary" in report
    assert "findings" in report
    assert "workflow_trace" in report


def test_supervisor_runs_risk_scan_before_workflow(tmp_path):
    p = _write(tmp_path, "x.elf", b"\x7fELF" + b"\x00" * 60)
    prov = ScriptedProvider([
        LLMResponse(content=None, tool_calls=[ToolCall(name="risk_scan", arguments={}, id="1")]),
        LLMResponse(content="risk scan done"),
        LLMResponse(content='{"binary_type":"ctf","nodes":['
                           '{"id":"n1","sub_task":"solve","specialist":"symbolic"}],"edges":[]}',
                     tool_calls=None),
    ])
    malware = FakeSpecialist({"risk_level": "MEDIUM", "risk_hints": ["is_dll"]})
    symbolic = FakeSpecialist({"flag": "CTF{x}"})
    sup = Supervisor(provider=prov, sandbox=None,
                     specialists={"malware": malware, "symbolic": symbolic})
    report = sup.run(binary_path=p, task="find flag")
    # malware specialist was invoked for the risk scan
    assert malware.calls[0]["task"].lower().startswith("risk")
    assert report["risk_level"] == "MEDIUM"
    # the workflow executed the symbolic node
    assert symbolic.calls  # symbolic ran during workflow execution
    assert symbolic.calls[-1]["task"] == "solve"


def test_supervisor_falls_back_to_bundled_playbook_when_synth_fails(tmp_path):
    p = _write(tmp_path, "x.exe",
               bb.build_pe_header(bits=64, machine=bb.IMAGE_FILE_MACHINE_AMD64))
    # synth returns garbage; engine exhausts retries and falls back to the bundled template
    prov = ScriptedProvider([
        LLMResponse(content=None, tool_calls=[ToolCall(name="risk_scan", arguments={}, id="1")]),
        LLMResponse(content="scanned"),
        LLMResponse(content="not json"),
        LLMResponse(content="still not json"),
    ])
    sup = Supervisor(provider=prov, sandbox=None,
                     specialists={"malware": FakeSpecialist({"risk_level": "LOW"}),
                                  "static": FakeSpecialist({"functions": ["main"]}),
                                  "symbolic": FakeSpecialist({"flag": "ok"}),
                                  "dynamic": FakeSpecialist({"executed": True})},
                     playbooks_dir=None)
    report = sup.run(binary_path=p, task="bypass")
    # fell back to crackme template which has 5 nodes (n1..n5)
    wf = report["workflow"]
    assert len(wf["nodes"]) == 5
    assert wf["binary_type"] == "crackme"


def test_supervisor_adapts_when_static_finds_vm(tmp_path):
    p = _write(tmp_path, "x.exe",
               bb.append_markers(bb.build_pe_header(bits=64,
                            machine=bb.IMAGE_FILE_MACHINE_AMD64), [b"VMProtect"]))
    # 1-2: risk scan, 3: synth a simple workflow, then static returns vm=True (anomaly),
    # 4: adapt patch (insert deobf node), then execution resumes
    prov = ScriptedProvider([
        LLMResponse(content=None, tool_calls=[ToolCall(name="risk_scan", arguments={}, id="1")]),
        LLMResponse(content="scanned"),
        LLMResponse(content='{"binary_type":"packed_vm","nodes":['
                           '{"id":"n1","sub_task":"scan","specialist":"malware"},'
                           '{"id":"n2","sub_task":"list funcs","specialist":"static"}],'
                           '"edges":[{"from_node":"n1","to_node":"n2"}]}',
                     tool_calls=None),
        # adapt patch: insert a deobfuscation node after n2
        LLMResponse(content='{"action":"insert_after","node_id":"n2",'
                           '"new_node":{"id":"n2a","sub_task":"lift VM",'
                           '"specialist":"deobfuscation","tool":"lift_vm_handler"},'
                           '"reason":"VM detected; devirtualize"}',
                     tool_calls=None),
    ])
    malware = FakeSpecialist({"risk_level": "MEDIUM"})
    static = FakeSpecialist({"vm": True, "functions": ["dispatch"]})
    deobf = FakeSpecialist({"lifted_opcodes": 3})
    sup = Supervisor(provider=prov, sandbox=None, specialists={
        "malware": malware, "static": static, "deobfuscation": deobf})
    report = sup.run(binary_path=p, task="devirtualize")
    # the inserted deobf node ran
    assert deobf.calls
    assert deobf.calls[-1]["task"] == "lift VM"
    # adapt reason recorded in workflow trace
    adapt_steps = [s for s in report["workflow_trace"] if s["action"] == "adapt"]
    assert len(adapt_steps) >= 1
    assert adapt_steps[0]["anomaly"] == "vm_detected"


def test_supervisor_record_includes_workflow_dict(tmp_path):
    p = _write(tmp_path, "x.elf", b"\x7fELF" + b"\x00" * 60)
    prov = ScriptedProvider([
        LLMResponse(content=None, tool_calls=[ToolCall(name="risk_scan", arguments={}, id="1")]),
        LLMResponse(content="done"),
        LLMResponse(content='{"binary_type":"ctf","nodes":['
                           '{"id":"n1","sub_task":"solve","specialist":"symbolic"}],"edges":[]}',
                     tool_calls=None),
    ])
    sup = Supervisor(provider=prov, sandbox=None,
                     specialists={"malware": FakeSpecialist({"risk_level": "LOW"}),
                                  "symbolic": FakeSpecialist({"flag": "CTF{y}"})})
    report = sup.run(binary_path=p, task="find flag")
    assert "workflow" in report
    assert report["workflow"]["nodes"][0]["id"] == "n1"
