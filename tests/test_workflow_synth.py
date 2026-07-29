"""Tests for WorkflowEngine.synthesize — LLM synthesis of the declarative DAG.

Stage 8b: the Supervisor + LLM produce a JSON DAG; the engine parses + schema-validates
it, re-prompts on malformed/invalid output, and falls back to a provided playbook template
when the LLM keeps failing. A scripted provider stands in for the cloud LLM.
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
from agent.llm.provider import LLMResponse  # noqa: E402
from agent.core.workflow import WorkflowEngine  # noqa: E402


class ScriptedProvider:
    def __init__(self, responses):
        self._r = list(responses)
        self.calls = 0
        self.all_messages: list[list[dict]] = []

    def complete(self, messages, tools=None, **kw):
        self.calls += 1
        self.all_messages.append(list(messages))
        return self._r.pop(0)


def _dag_json(content: str) -> LLMResponse:
    return LLMResponse(content=content, tool_calls=None)


def _binary_info(**over):
    base = {"path": "x.exe", "format": "PE", "arch": "x86_64", "bits": 64,
            "endian": "little", "entry": 0x401000, "sha256": "abc", "size": 100,
            "risk_hints": []}
    base.update(over)
    from tools.binary import BinaryInfo
    return BinaryInfo(**base)


def test_synth_parses_llm_dag_json():
    dag = {
        "binary_type": "crackme",
        "nodes": [
            {"id": "n1", "sub_task": "scan risk", "specialist": "malware", "tool": "risk_scan"},
            {"id": "n2", "sub_task": "list functions", "specialist": "static", "tool": "list_functions"},
        ],
        "edges": [{"from_node": "n1", "to_node": "n2", "condition": "success"}],
    }
    prov = ScriptedProvider([_dag_json(json.dumps(dag))])
    eng = WorkflowEngine(provider=prov, sandbox=None, specialists={}, playbooks_dir=None)
    wf = eng.synthesize(task="bypass license", binary_info=_binary_info())
    assert wf.binary_type == "crackme"
    assert [n.id for n in wf.nodes] == ["n1", "n2"]
    assert wf.get_node("n1").specialist == "malware"
    assert wf.get_node("n1").tool == "risk_scan"
    assert wf.edges == [WorkflowEdge(from_node="n1", to_node="n2", condition="success")]
    assert wf.validate() == []


def test_synth_reprompts_on_malformed_json():
    prov = ScriptedProvider([
        _dag_json("not json at all {"),
        _dag_json(json.dumps({
            "binary_type": "ctf",
            "nodes": [{"id": "n1", "sub_task": "scan", "specialist": "malware"}],
            "edges": [],
        })),
    ])
    eng = WorkflowEngine(provider=prov, sandbox=None, specialists={}, playbooks_dir=None)
    wf = eng.synthesize(task="find flag", binary_info=_binary_info())
    assert prov.calls == 2
    assert wf.binary_type == "ctf"
    assert [n.id for n in wf.nodes] == ["n1"]


def test_synth_reprompts_on_invalid_dag_cycle():
    cyclic = {
        "binary_type": "unknown",
        "nodes": [
            {"id": "n1", "sub_task": "a", "specialist": "malware"},
            {"id": "n2", "sub_task": "b", "specialist": "static"},
        ],
        "edges": [
            {"from_node": "n1", "to_node": "n2"},
            {"from_node": "n2", "to_node": "n1"},
        ],
    }
    clean = {
        "binary_type": "unknown",
        "nodes": [
            {"id": "n1", "sub_task": "a", "specialist": "malware"},
            {"id": "n2", "sub_task": "b", "specialist": "static"},
        ],
        "edges": [{"from_node": "n1", "to_node": "n2"}],
    }
    prov = ScriptedProvider([_dag_json(json.dumps(cyclic)), _dag_json(json.dumps(clean))])
    eng = WorkflowEngine(provider=prov, sandbox=None, specialists={}, playbooks_dir=None)
    wf = eng.synthesize(task="t", binary_info=_binary_info())
    assert prov.calls == 2
    assert wf.validate() == []


def test_synth_falls_back_to_playbook_when_llm_exhausted():
    # LLM keeps producing garbage past max retries; engine falls back to the supplied template.
    prov = ScriptedProvider([_dag_json("garbage"), _dag_json("still garbage")])
    fallback = Workflow(
        nodes=[WorkflowNode(id="p1", sub_task="scan", specialist="malware")],
        edges=[],
        binary_type="malware",
    )
    eng = WorkflowEngine(provider=prov, sandbox=None, specialists={}, playbooks_dir=None)
    wf = eng.synthesize(task="t", binary_info=_binary_info(),
                       fallback_playbook=fallback, max_retries=1)
    assert [n.id for n in wf.nodes] == ["p1"]
    assert wf.binary_type == "malware"
