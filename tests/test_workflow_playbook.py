"""Tests for the playbook library — saved workflow templates keyed by binary type.

Stage 8g: a successful (or analyst-curated) workflow is saved as a parametrized template.
save_playbook strips node outputs/statuses (a template is status-agnostic) and writes the
DAG to a JSON file in the playbooks directory. load_playbook rebuilds a fresh Workflow with
all nodes 'pending'. list_playbooks returns the available names.
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


def _wf() -> Workflow:
    return Workflow(nodes=[
        WorkflowNode(id="n1", sub_task="risk scan", specialist="malware", tool="risk_scan"),
        WorkflowNode(id="n2", sub_task="list funcs", specialist="static", tool="list_functions"),
    ], edges=[WorkflowEdge(from_node="n1", to_node="n2")], binary_type="crackme")


def test_save_playbook_writes_template_json(tmp_path):
    wf = _wf()
    eng = WorkflowEngine(provider=None, sandbox=None, specialists={}, playbooks_dir=tmp_path)
    eng.save_playbook(wf, "crackme")
    out = tmp_path / "crackme.json"
    assert out.exists()
    import json
    d = json.loads(out.read_text())
    assert d["binary_type"] == "crackme"
    assert [n["id"] for n in d["workflow"]["nodes"]] == ["n1", "n2"]


def test_save_playbook_strips_node_outputs_and_status(tmp_path):
    wf = _wf()
    wf.get_node("n1").status = "done"
    wf.get_node("n1").outputs = {"risk": "LOW"}
    wf.get_node("n2").status = "skipped"
    eng = WorkflowEngine(provider=None, sandbox=None, specialists={}, playbooks_dir=tmp_path)
    eng.save_playbook(wf, "crackme")
    loaded = eng.load_playbook("crackme")
    assert loaded.get_node("n1").status == "pending"
    assert loaded.get_node("n1").outputs == {}
    assert loaded.get_node("n2").status == "pending"
    assert loaded.get_node("n2").error is None


def test_load_playbook_rebuilds_workflow(tmp_path):
    wf = _wf()
    eng = WorkflowEngine(provider=None, sandbox=None, specialists={}, playbooks_dir=tmp_path)
    eng.save_playbook(wf, "crackme")
    loaded = eng.load_playbook("crackme")
    assert loaded.binary_type == "crackme"
    assert [n.id for n in loaded.nodes] == ["n1", "n2"]
    assert loaded.get_node("n1").tool == "risk_scan"
    assert loaded.edges == [WorkflowEdge(from_node="n1", to_node="n2", condition="success")]
    assert loaded.validate() == []


def test_list_playbooks_returns_available_names(tmp_path):
    eng = WorkflowEngine(provider=None, sandbox=None, specialists={}, playbooks_dir=tmp_path)
    eng.save_playbook(_wf(), "crackme")
    eng.save_playbook(_wf(), "ctf")
    names = eng.list_playbooks()
    assert set(names) == {"crackme", "ctf"}


def test_load_playbook_missing_raises(tmp_path):
    eng = WorkflowEngine(provider=None, sandbox=None, specialists={}, playbooks_dir=tmp_path)
    with pytest.raises(FileNotFoundError):
        eng.load_playbook("nonexistent")


def test_load_playbook_no_dir_raises(tmp_path):
    eng = WorkflowEngine(provider=None, sandbox=None, specialists={}, playbooks_dir=None)
    with pytest.raises((FileNotFoundError, ValueError)):
        eng.load_playbook("crackme")
