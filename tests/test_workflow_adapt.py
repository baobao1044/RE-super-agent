"""Tests for WorkflowEngine adaptive loop — self-modifying DAG.

Stage 8d: when a node returns an anomaly (VM detected, symbolic path explosion, node
failure), the engine asks the LLM to propose a structural patch (insert_after /
replace_node / switch_specialist / backtrack), validates it, applies it, and records the
reason in the workspace workflow trace. A scripted provider stands in for the cloud LLM.

Anomaly detection (`detect_anomaly`) is a pure heuristic over the node's result dict so
the engine can trigger adaptation deterministically without waiting for the LLM.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent.core.workflow import Workflow, WorkflowEdge, WorkflowNode  # noqa: E402
from agent.core.workflow import WorkflowEngine  # noqa: E402
from agent.llm.provider import LLMResponse  # noqa: E402
from agent.state.workspace import Workspace  # noqa: E402


class ScriptedProvider:
    def __init__(self, responses):
        self._r = list(responses)
        self.calls = 0

    def complete(self, messages, tools=None, **kw):
        self.calls += 1
        return self._r.pop(0)


def _patch(content: str) -> LLMResponse:
    return LLMResponse(content=content, tool_calls=None)


# ------------------------------------------------------------------ detect
def test_detect_anomaly_none_on_clean_result():
    assert WorkflowEngine.detect_anomaly({"risk_level": "LOW", "functions": ["main"]}) is None


def test_detect_anomaly_vm_detected():
    assert WorkflowEngine.detect_anomaly({"vm": True}) == "vm_detected"
    assert WorkflowEngine.detect_anomaly({"obfuscated": "VMProtect"}) == "vm_detected"


def test_detect_anomaly_symbolic_explode():
    assert WorkflowEngine.detect_anomaly({"path_explosion": True}) == "symbolic_explode"
    assert WorkflowEngine.detect_anomaly({"states_explored": 10_000_000}) == "symbolic_explode"


def test_detect_anomaly_node_failed_when_error_present():
    assert WorkflowEngine.detect_anomaly({"error": "decompile failed"}) == "node_failed"


# ------------------------------------------------------------------ adapt
def test_adapt_inserts_deobf_node_on_vm_detected():
    wf = Workflow(nodes=[
        WorkflowNode(id="n1", sub_task="list funcs", specialist="static",
                    outputs={"vm": True}, status="done"),
        WorkflowNode(id="n2", sub_task="solve", specialist="symbolic"),
    ], edges=[WorkflowEdge(from_node="n1", to_node="n2")])
    patch = {
        "action": "insert_after", "node_id": "n1",
        "new_node": {"id": "n1a", "sub_task": "lift VM handlers",
                      "specialist": "deobfuscation", "tool": "lift_vm_handler"},
        "reason": "VM detected by static analysis; devirtualize before symbolic solve",
    }
    prov = ScriptedProvider([_patch(json.dumps(patch))])
    eng = WorkflowEngine(provider=prov, sandbox=None, specialists={})
    ws = Workspace(session_id="a1")
    eng.adapt(wf, anomaly="vm_detected", anomaly_node_id="n1", workspace=ws)
    assert wf.get_node("n1a") is not None
    assert wf.get_node("n1a").specialist == "deobfuscation"
    # new node wired between n1 and n2
    assert wf.get_node("n2").status == "pending"
    assert wf.validate() == []


def test_adapt_switches_specialist_on_node_failed():
    wf = Workflow(nodes=[
        WorkflowNode(id="n1", sub_task="decompile", specialist="ghidra",
                    status="failed", error="no ghidra"),
    ], edges=[])
    patch = {
        "action": "switch_specialist", "node_id": "n1",
        "specialist": "static",
        "reason": "ghidra unavailable; retry decompile with r2 backend",
    }
    prov = ScriptedProvider([_patch(json.dumps(patch))])
    eng = WorkflowEngine(provider=prov, sandbox=None, specialists={})
    ws = Workspace(session_id="a2")
    eng.adapt(wf, anomaly="node_failed", anomaly_node_id="n1", workspace=ws)
    assert wf.get_node("n1").specialist == "static"
    assert wf.get_node("n1").status == "pending"  # reset for re-run


def test_adapt_reprompts_on_malformed_patch():
    wf = Workflow(nodes=[
        WorkflowNode(id="n1", sub_task="s", specialist="malware", status="failed"),
    ], edges=[])
    good = {"action": "switch_specialist", "node_id": "n1",
            "specialist": "static", "reason": "retry"}
    prov = ScriptedProvider([_patch("not json"), _patch(json.dumps(good))])
    eng = WorkflowEngine(provider=prov, sandbox=None, specialists={})
    ws = Workspace(session_id="a3")
    eng.adapt(wf, anomaly="node_failed", anomaly_node_id="n1", workspace=ws)
    assert prov.calls == 2
    assert wf.get_node("n1").specialist == "static"


def test_adapt_records_reason_in_workflow_trace():
    wf = Workflow(nodes=[
        WorkflowNode(id="n1", sub_task="solve", specialist="symbolic",
                    status="failed", error="explode"),
    ], edges=[])
    patch = {"action": "backtrack", "node_id": "n1",
             "reason": "symbolic exploded; backtracking to add trace-narrowing"}
    prov = ScriptedProvider([_patch(json.dumps(patch))])
    eng = WorkflowEngine(provider=prov, sandbox=None, specialists={})
    ws = Workspace(session_id="a4")
    eng.adapt(wf, anomaly="symbolic_explode", anomaly_node_id="n1", workspace=ws)
    trace = [s for s in ws.workflow_trace if s["action"] == "adapt"]
    assert len(trace) == 1
    assert "symbolic exploded" in trace[0]["reason"] or "explode" in trace[0]["reason"]
    assert trace[0]["anomaly"] == "symbolic_explode"
