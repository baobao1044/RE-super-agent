"""Tests for agent.core.workflow — the dynamic workflow engine.

Stage 8a: the declarative DAG data model (WorkflowNode / WorkflowEdge / Workflow) plus
validation (duplicate ids, dangling edges, cycle detection, topological order).

Engine availability-guarded: pure-logic, no Docker / cloud LLM required for the model.
A scripted provider + fake sandbox are injected for synth / execute / adapt / code-gen
tests in the companion files.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent.core.workflow import Workflow, WorkflowEdge, WorkflowNode  # noqa: E402


# --------------------------------------------------------------------------- model
def test_node_defaults_pending():
    n = WorkflowNode(id="n1", sub_task="scan", specialist="malware")
    assert n.id == "n1"
    assert n.specialist == "malware"
    assert n.status == "pending"
    assert n.tool is None
    assert n.outputs == {}
    assert n.error is None


def test_workflow_get_node_and_successors():
    wf = Workflow(nodes=[
        WorkflowNode(id="n1", sub_task="a", specialist="malware"),
        WorkflowNode(id="n2", sub_task="b", specialist="static"),
        WorkflowNode(id="n3", sub_task="c", specialist="symbolic"),
    ], edges=[
        WorkflowEdge(from_node="n1", to_node="n2"),
        WorkflowEdge(from_node="n1", to_node="n3", condition="fail"),
        WorkflowEdge(from_node="n2", to_node="n3"),
    ])
    assert wf.node_ids == ["n1", "n2", "n3"]
    assert wf.get_node("n2").sub_task == "b"
    assert wf.get_node("nope") is None
    # successors default to success-condition edges only
    succ = [n.id for n in wf.successors("n1")]
    assert succ == ["n2"]
    # successors(condition="fail")
    assert [n.id for n in wf.successors("n1", condition="fail")] == ["n3"]


def test_validate_clean_dag_no_errors():
    wf = Workflow(nodes=[
        WorkflowNode(id="n1", sub_task="a", specialist="malware"),
        WorkflowNode(id="n2", sub_task="b", specialist="static"),
    ], edges=[WorkflowEdge(from_node="n1", to_node="n2")])
    assert wf.validate() == []


def test_validate_duplicate_node_ids():
    wf = Workflow(nodes=[
        WorkflowNode(id="n1", sub_task="a", specialist="malware"),
        WorkflowNode(id="n1", sub_task="dup", specialist="static"),
    ], edges=[])
    errs = wf.validate()
    assert any("duplicate" in e for e in errs)


def test_validate_dangling_edge():
    wf = Workflow(nodes=[
        WorkflowNode(id="n1", sub_task="a", specialist="malware"),
    ], edges=[WorkflowEdge(from_node="n1", to_node="ghost")])
    errs = wf.validate()
    assert any("ghost" in e for e in errs)


def test_validate_cycle_detected():
    wf = Workflow(nodes=[
        WorkflowNode(id="n1", sub_task="a", specialist="malware"),
        WorkflowNode(id="n2", sub_task="b", specialist="static"),
        WorkflowNode(id="n3", sub_task="c", specialist="symbolic"),
    ], edges=[
        WorkflowEdge(from_node="n1", to_node="n2"),
        WorkflowEdge(from_node="n2", to_node="n3"),
        WorkflowEdge(from_node="n3", to_node="n1"),
    ])
    errs = wf.validate()
    assert any("cycle" in e.lower() for e in errs)


def test_topological_order_respects_edges():
    wf = Workflow(nodes=[
        WorkflowNode(id="n3", sub_task="c", specialist="symbolic"),
        WorkflowNode(id="n1", sub_task="a", specialist="malware"),
        WorkflowNode(id="n2", sub_task="b", specialist="static"),
    ], edges=[
        WorkflowEdge(from_node="n1", to_node="n2"),
        WorkflowEdge(from_node="n2", to_node="n3"),
    ])
    order = [n.id for n in wf.topological_order()]
    assert order == ["n1", "n2", "n3"]


def test_topological_order_raises_on_cycle():
    wf = Workflow(nodes=[
        WorkflowNode(id="n1", sub_task="a", specialist="malware"),
        WorkflowNode(id="n2", sub_task="b", specialist="static"),
    ], edges=[
        WorkflowEdge(from_node="n1", to_node="n2"),
        WorkflowEdge(from_node="n2", to_node="n1"),
    ])
    with pytest.raises(ValueError):
        wf.topological_order()
