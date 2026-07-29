"""Tests for WorkflowEngine.execute — topological DAG execution.

Stage 8c: the engine runs nodes in dependency order, dispatching each to the right
specialist (specialists injected as a dict of fakes). Branch conditions gate successors:
a node on a 'success' edge is skipped when its predecessor failed; a node on a 'fail' edge
runs only when its predecessor failed; 'always' edges run regardless. Each step is recorded
in the workspace workflow trace for observability.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent.core.workflow import Workflow, WorkflowEdge, WorkflowNode  # noqa: E402
from agent.core.workflow import WorkflowEngine  # noqa: E402
from agent.state.workspace import Workspace  # noqa: E402


class FakeSpecialist:
    """A stand-in specialist whose run() returns a fixed result dict."""
    def __init__(self, name: str, result: dict):
        self.name = name
        self.result = result
        self.calls: list[dict] = []

    def run(self, *, task: str, binary_path, workspace: Workspace, **kw) -> dict:
        self.calls.append({"task": task, "binary_path": str(binary_path)})
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def _bin(tmp_path) -> Path:
    p = tmp_path / "x.bin"
    p.write_bytes(b"\x7fELF" + b"\x00" * 60)
    return p


def test_execute_runs_nodes_in_topo_order_and_stores_outputs(tmp_path):
    wf = Workflow(nodes=[
        WorkflowNode(id="n1", sub_task="scan risk", specialist="malware"),
        WorkflowNode(id="n2", sub_task="list functions", specialist="static"),
    ], edges=[WorkflowEdge(from_node="n1", to_node="n2")])
    malware = FakeSpecialist("malware", {"risk_level": "LOW"})
    static = FakeSpecialist("static", {"functions": ["main"]})
    eng = WorkflowEngine(provider=None, sandbox=None,
                        specialists={"malware": malware, "static": static})
    ws = Workspace(session_id="e1")
    eng.execute(wf, _bin(tmp_path), ws)
    assert wf.get_node("n1").status == "done"
    assert wf.get_node("n1").outputs == {"risk_level": "LOW"}
    assert wf.get_node("n2").status == "done"
    assert wf.get_node("n2").outputs == {"functions": ["main"]}
    # right specialist dispatched with right args
    assert malware.calls[0]["task"] == "scan risk"
    assert static.calls[0]["task"] == "list functions"


def test_execute_skips_success_branch_when_predecessor_failed(tmp_path):
    wf = Workflow(nodes=[
        WorkflowNode(id="n1", sub_task="scan", specialist="malware"),
        WorkflowNode(id="n2", sub_task="solve", specialist="symbolic"),
    ], edges=[WorkflowEdge(from_node="n1", to_node="n2", condition="success")])
    eng = WorkflowEngine(provider=None, sandbox=None, specialists={
        "malware": FakeSpecialist("malware", {"error": "scan failed"}),
        "symbolic": FakeSpecialist("symbolic", {"flag": "x"}),
    })
    ws = Workspace(session_id="e2")
    eng.execute(wf, _bin(tmp_path), ws)
    assert wf.get_node("n1").status == "failed"
    assert wf.get_node("n2").status == "skipped"


def test_execute_runs_fail_branch_when_predecessor_fails(tmp_path):
    wf = Workflow(nodes=[
        WorkflowNode(id="n1", sub_task="scan", specialist="malware"),
        WorkflowNode(id="n2", sub_task="fallback static", specialist="static"),
    ], edges=[WorkflowEdge(from_node="n1", to_node="n2", condition="fail")])
    static = FakeSpecialist("static", {"functions": ["a"]})
    eng = WorkflowEngine(provider=None, sandbox=None, specialists={
        "malware": FakeSpecialist("malware", {"error": "scan failed"}),
        "static": static,
    })
    ws = Workspace(session_id="e3")
    eng.execute(wf, _bin(tmp_path), ws)
    assert wf.get_node("n1").status == "failed"
    assert wf.get_node("n2").status == "done"
    assert static.calls  # the fail branch ran


def test_execute_always_edge_runs_regardless(tmp_path):
    wf = Workflow(nodes=[
        WorkflowNode(id="n1", sub_task="scan", specialist="malware"),
        WorkflowNode(id="n2", sub_task="report", specialist="static"),
    ], edges=[WorkflowEdge(from_node="n1", to_node="n2", condition="always")])
    report = FakeSpecialist("static", {"report": "done"})
    eng = WorkflowEngine(provider=None, sandbox=None, specialists={
        "malware": FakeSpecialist("malware", {"error": "boom"}),
        "static": report,
    })
    ws = Workspace(session_id="e4")
    eng.execute(wf, _bin(tmp_path), ws)
    assert wf.get_node("n1").status == "failed"
    assert wf.get_node("n2").status == "done"  # always runs


def test_execute_records_workflow_trace(tmp_path):
    wf = Workflow(nodes=[
        WorkflowNode(id="n1", sub_task="scan risk", specialist="malware"),
    ], edges=[])
    eng = WorkflowEngine(provider=None, sandbox=None,
                        specialists={"malware": FakeSpecialist("malware", {"risk_level": "LOW"})})
    ws = Workspace(session_id="e5")
    eng.execute(wf, _bin(tmp_path), ws)
    assert len(ws.workflow_trace) == 1
    step = ws.workflow_trace[0]
    assert step["action"] == "execute_node"
    assert step["node"] == "n1"


def test_execute_marks_node_failed_on_exception(tmp_path):
    wf = Workflow(nodes=[
        WorkflowNode(id="n1", sub_task="scan", specialist="malware"),
    ], edges=[])
    eng = WorkflowEngine(provider=None, sandbox=None, specialists={
        "malware": FakeSpecialist("malware", RuntimeError("kaboom")),
    })
    ws = Workspace(session_id="e6")
    eng.execute(wf, _bin(tmp_path), ws)
    assert wf.get_node("n1").status == "failed"
    assert "kaboom" in (wf.get_node("n1").error or "")
