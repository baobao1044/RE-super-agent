"""Tests for WorkflowEngine code-gen node — LLM-generated Python run in the sandbox.

Stage 8f: a 'codegen' specialist node asks the LLM for a Python snippet, writes it to a temp
file, and runs it inside the Docker sandbox (NEVER on host). The snippet's JSON stdout
result is recorded in the node's outputs and as a workspace finding. If the sandbox is
unavailable, the node degrades to a failed 'static-only' error (never host exec).

The sandbox here is a fake that records the written script path and returns a canned
result, proving the engine persists the snippet to disk before running it.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent.core.workflow import Workflow, WorkflowNode  # noqa: E402
from agent.core.workflow import WorkflowEngine  # noqa: E402
from agent.llm.provider import LLMResponse  # noqa: E402
from agent.state.workspace import Workspace  # noqa: E402


class FakeSandbox:
    """Records the script path the engine wrote; returns a canned result."""
    def __init__(self, result: dict):
        self.result = result
        self.last_script_path: str | None = None
        self.last_script_text: str | None = None

    def run_codegen(self, script_path, *, image="re-agent:full", input_path=None, timeout=120):
        self.last_script_path = str(script_path)
        self.last_script_text = Path(script_path).read_text()
        return self.result


class NoSandbox:
    """Always raises — simulates Docker unavailable."""
    def run_codegen(self, *a, **kw):
        from tools.sandbox import SandboxUnavailableError
        raise SandboxUnavailableError("no docker")


class ScriptedProvider:
    def __init__(self, responses):
        self._r = list(responses)
        self.calls = 0

    def complete(self, messages, tools=None, **kw):
        self.calls += 1
        return self._r.pop(0)


def _bin(tmp_path) -> Path:
    p = tmp_path / "x.bin"
    p.write_bytes(b"\x7fELF" + b"\x00" * 60)
    return p


# ----------------------------------------------------------------- dispatch
def test_codegen_node_runs_llm_snippet_in_sandbox(tmp_path):
    node = WorkflowNode(id="n1", sub_task="compute VM dispatch table",
                        specialist="codegen")
    prov = ScriptedProvider([
        LLMResponse(content="import json\nprint(json.dumps({'dispatch': 0x402000, 'opcodes': 3}))",
                    tool_calls=None),
    ])
    sb = FakeSandbox({"ok": True, "result": {"dispatch": 0x402000, "opcodes": 3}, "exit_code": 0})
    eng = WorkflowEngine(provider=prov, sandbox=sb, specialists={})
    ws = Workspace(session_id="c1")
    eng.execute(Workflow(nodes=[node], edges=[]), _bin(tmp_path), ws, codegen_dir=tmp_path)
    assert node.status == "done"
    assert node.outputs["dispatch"] == 0x402000
    # the snippet was persisted to a file under codegen_dir before running
    assert sb.last_script_path is not None
    assert sb.last_script_text == \
        "import json\nprint(json.dumps({'dispatch': 0x402000, 'opcodes': 3}))"
    assert str(tmp_path) in sb.last_script_path


def test_codegen_node_records_result_as_workspace_finding(tmp_path):
    node = WorkflowNode(id="n1", sub_task="build VM spec", specialist="codegen")
    prov = ScriptedProvider([LLMResponse(content="print(1)", tool_calls=None)])
    sb = FakeSandbox({"ok": True, "result": {"vm": True, "handlers": 2}, "exit_code": 0})
    eng = WorkflowEngine(provider=prov, sandbox=sb, specialists={})
    ws = Workspace(session_id="c2")
    eng.execute(Workflow(nodes=[node], edges=[]), _bin(tmp_path), ws, codegen_dir=tmp_path)
    codegen_findings = [f for f in ws.findings if f["kind"] == "codegen_result"]
    assert len(codegen_findings) == 1
    assert codegen_findings[0]["source"] == "codegen"


def test_codegen_node_records_workflow_trace(tmp_path):
    node = WorkflowNode(id="n1", sub_task="custom reasoning", specialist="codegen")
    prov = ScriptedProvider([LLMResponse(content="print(1)", tool_calls=None)])
    sb = FakeSandbox({"ok": True, "result": {"x": 1}, "exit_code": 0})
    eng = WorkflowEngine(provider=prov, sandbox=sb, specialists={})
    ws = Workspace(session_id="c3")
    eng.execute(Workflow(nodes=[node], edges=[]), _bin(tmp_path), ws, codegen_dir=tmp_path)
    trace = [s for s in ws.workflow_trace if s["node"] == "n1"]
    assert len(trace) == 1
    assert trace[0]["specialist"] == "codegen"


def test_codegen_node_fails_when_sandbox_unavailable(tmp_path):
    node = WorkflowNode(id="n1", sub_task="custom reasoning", specialist="codegen")
    prov = ScriptedProvider([LLMResponse(content="print(1)", tool_calls=None)])
    eng = WorkflowEngine(provider=prov, sandbox=NoSandbox(), specialists={})
    ws = Workspace(session_id="c4")
    eng.execute(Workflow(nodes=[node], edges=[]), _bin(tmp_path), ws, codegen_dir=tmp_path)
    assert node.status == "failed"
    assert "sandbox" in (node.error or "").lower() or "docker" in (node.error or "").lower()


def test_codegen_node_fails_on_snippet_error(tmp_path):
    node = WorkflowNode(id="n1", sub_task="custom reasoning", specialist="codegen")
    prov = ScriptedProvider([LLMResponse(content="print(1)", tool_calls=None)])
    sb = FakeSandbox({"ok": False, "error": "NameError: name 'x' is not defined",
                      "exit_code": 1})
    eng = WorkflowEngine(provider=prov, sandbox=sb, specialists={})
    ws = Workspace(session_id="c5")
    eng.execute(Workflow(nodes=[node], edges=[]), _bin(tmp_path), ws, codegen_dir=tmp_path)
    assert node.status == "failed"
    assert "NameError" in (node.error or "")


def test_codegen_node_reprompts_on_empty_snippet(tmp_path):
    node = WorkflowNode(id="n1", sub_task="custom reasoning", specialist="codegen")
    prov = ScriptedProvider([
        LLMResponse(content="", tool_calls=None),
        LLMResponse(content="print('ok')", tool_calls=None),
    ])
    sb = FakeSandbox({"ok": True, "result": {"x": 1}, "exit_code": 0})
    eng = WorkflowEngine(provider=prov, sandbox=sb, specialists={})
    ws = Workspace(session_id="c6")
    eng.execute(Workflow(nodes=[node], edges=[]), _bin(tmp_path), ws, codegen_dir=tmp_path)
    assert prov.calls == 2
    assert node.status == "done"
