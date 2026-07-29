"""Tests for WorkflowEngine checkpoint + resume — durable workflow continuation.

Stage 8e: a long-running RE analysis can resume after interruption. The engine checkpoints
the full state (the serialized Workflow DAG with node statuses + the Workspace) to a JSON
file, and resume() loads it and re-runs only pending nodes (skipping done ones). The
checkpoint records the binary type and which nodes were completed.
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
    def __init__(self, result):
        self.result = result
        self.run_count = 0

    def run(self, *, task, binary_path, workspace, **kw):
        self.run_count += 1
        return self.result


def _bin(tmp_path) -> Path:
    p = tmp_path / "x.bin"
    p.write_bytes(b"\x7fELF" + b"\x00" * 60)
    return p


def test_checkpoint_save_creates_json(tmp_path):
    wf = Workflow(nodes=[
        WorkflowNode(id="n1", sub_task="scan", specialist="malware",
                    status="done", outputs={"risk": "LOW"}),
        WorkflowNode(id="n2", sub_task="solve", specialist="symbolic", status="pending"),
    ], edges=[WorkflowEdge(from_node="n1", to_node="n2")], binary_type="crackme")
    ws = Workspace(session_id="r1")
    eng = WorkflowEngine(provider=None, sandbox=None, specialists={})
    ckpt = tmp_path / "ckpt.json"
    eng.checkpoint_save(wf, ws, ckpt)
    assert ckpt.exists()
    import json
    d = json.loads(ckpt.read_text())
    assert d["binary_type"] == "crackme"
    assert d["workflow"]["nodes"][0]["status"] == "done"
    assert d["workspace"]["session_id"] == "r1"


def test_resume_loads_workflow_and_workspace(tmp_path):
    wf = Workflow(nodes=[
        WorkflowNode(id="n1", sub_task="scan", specialist="malware",
                    status="done", outputs={"risk": "LOW"}),
        WorkflowNode(id="n2", sub_task="solve", specialist="symbolic", status="pending"),
    ], edges=[WorkflowEdge(from_node="n1", to_node="n2")], binary_type="ctf")
    ws = Workspace(session_id="r2")
    ws.add_finding(kind="note", summary="halfway")
    eng = WorkflowEngine(provider=None, sandbox=None, specialists={})
    ckpt = tmp_path / "ckpt.json"
    eng.checkpoint_save(wf, ws, ckpt)

    loaded_wf, loaded_ws = WorkflowEngine.checkpoint_load(ckpt)
    assert loaded_wf.binary_type == "ctf"
    assert loaded_wf.get_node("n1").status == "done"
    assert loaded_wf.get_node("n1").outputs == {"risk": "LOW"}
    assert loaded_ws.session_id == "r2"
    assert loaded_ws.findings[0]["summary"] == "halfway"


def test_resume_re_runs_only_pending_nodes(tmp_path):
    wf = Workflow(nodes=[
        WorkflowNode(id="n1", sub_task="scan", specialist="malware",
                    status="done", outputs={"risk": "LOW"}),
        WorkflowNode(id="n2", sub_task="solve", specialist="symbolic", status="pending"),
    ], edges=[WorkflowEdge(from_node="n1", to_node="n2")])
    ws = Workspace(session_id="r3")
    malware = FakeSpecialist({"risk": "LOW"})
    symbolic = FakeSpecialist({"flag": "CTF{x}"})
    eng = WorkflowEngine(provider=None, sandbox=None,
                        specialists={"malware": malware, "symbolic": symbolic})
    ckpt = tmp_path / "ckpt.json"
    eng.checkpoint_save(wf, ws, ckpt)

    loaded_wf, loaded_ws = WorkflowEngine.checkpoint_load(ckpt)
    eng.execute(loaded_wf, _bin(tmp_path), loaded_ws)
    assert malware.run_count == 0   # already done, not re-run
    assert symbolic.run_count == 1  # pending, re-run
    assert loaded_wf.get_node("n2").status == "done"


def test_resume_resets_running_node_to_pending(tmp_path):
    # a node interrupted mid-run (status='running') should resume from pending
    wf = Workflow(nodes=[
        WorkflowNode(id="n1", sub_task="scan", specialist="malware", status="running"),
    ], edges=[])
    ws = Workspace(session_id="r4")
    eng = WorkflowEngine(provider=None, sandbox=None, specialists={})
    ckpt = tmp_path / "ckpt.json"
    eng.checkpoint_save(wf, ws, ckpt)
    loaded_wf, loaded_ws = WorkflowEngine.checkpoint_load(ckpt)
    assert loaded_wf.get_node("n1").status == "pending"
