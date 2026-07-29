"""Supervisor — the top-level RE orchestrator.

Drives the full pipeline the user asked for:
  analyze binary -> malware risk scan -> synthesize the workflow DAG (with a bundled
  playbook as fallback) -> execute it, dispatching nodes to specialists and adapting on
  anomalies -> synthesize a final report from the workspace.

The risk scan always uses a real MalwareSpecialist (with the LLM provider + a pure-logic
risk registry) so the risk level is authoritative. Workflow execution dispatches each node
to the specialist registered under its name in `specialists` (injectable for tests). The
adaptive loop re-runs the engine after each anomaly-driven patch so inserted nodes execute.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Callable

from agent.core import playbooks as playbook_lib
from agent.core.planner import classify_binary_type
from agent.core.workflow import Workflow, WorkflowEngine
from agent.specialists.malware import MalwareSpecialist
from agent.state.workspace import Workspace
from tools.binary import analyze

log = logging.getLogger(__name__)


class Supervisor:
    def __init__(self, *, provider, sandbox=None, specialists: dict | None = None,
                 playbooks_dir: str | Path | None = None, codegen_dir=None,
                 risk_scan_registry: dict | None = None):
        self.provider = provider
        self.sandbox = sandbox
        self.specialists = specialists or {}
        self.playbooks_dir = playbooks_dir
        self.codegen_dir = codegen_dir
        self._risk_scan_registry = risk_scan_registry
        self.engine = WorkflowEngine(provider=provider, sandbox=sandbox,
                                     specialists=self.specialists,
                                     playbooks_dir=playbooks_dir)

    # --------------------------------------------------------------------- run
    def run(self, binary_path, task: str) -> dict:
        path = str(binary_path)
        info = analyze(path)
        ws = Workspace(session_id=info.sha256[:12] if info.sha256 else "session")

        # 1. Authoritative risk scan (real malware specialist + LLM + pure risk registry).
        ws.set_binary(info, risk_level="UNKNOWN")
        risk_result = self._run_risk_scan(path, task, ws)
        risk_level = risk_result.get("risk_level", "LOW")
        risk_hints = risk_result.get("risk_hints", []) or info.risk_hints
        ws.set_binary(info, risk_level=risk_level, risk_hints=risk_hints)

        # 2. Pick a bundled playbook as the synthesis fallback by guessed binary type.
        binary_type = self._guess_binary_type(risk_result, task)
        fallback = self._fallback_playbook(binary_type)

        # 3. Synthesize the workflow DAG (falls back to the playbook if the LLM fails).
        wf = self.engine.synthesize(task=task, binary_info=info,
                                    risk_assessment=risk_result,
                                    fallback_playbook=fallback)

        # 4. Execute with the adaptive self-modification loop.
        self._execute_adaptive(wf, path, ws)

        # 5. Synthesize the final report from the workspace.
        return self._synthesize_report(ws, wf, risk_level, task)

    # ------------------------------------------------------------- risk scan
    def _run_risk_scan(self, path: str, task: str, ws: Workspace) -> dict:
        # Prefer the injected 'malware' specialist (real MalwareSpecialist in a live
        # deployment, or a fake in tests) so the risk level is authoritative. Fall back to
        # constructing a real MalwareSpecialist with the LLM + a pure-logic risk registry.
        scanner = self.specialists.get("malware")
        if scanner is None:
            registry = self._risk_scan_registry or self._default_risk_registry(path)
            scanner = MalwareSpecialist(provider=self.provider, tools_registry=registry)
        try:
            return scanner.run(task=f"risk scan: {task}", binary_path=path, workspace=ws)
        except Exception as exc:  # noqa: BLE001 — degrade to a conservative default
            log.warning("risk scan failed: %s", exc)
            return {"risk_level": "MEDIUM", "risk_hints": [],
                    "recommendation": {"mode": "static_only", "reason": str(exc)}}

    @staticmethod
    def _default_risk_registry(path: str) -> dict[str, Callable]:
        """Pure-logic risk tools (no Docker / no engine required)."""
        from mcp_servers.malware.server import tool_extract_strings, tool_risk_scan
        return {
            "risk_scan": lambda a: tool_risk_scan(path),
            "extract_strings": lambda a: tool_extract_strings(path, a.get("min_len", 4)),
        }

    # --------------------------------------------------------- binary typing
    @staticmethod
    def _guess_binary_type(risk_result: dict, task: str) -> str:
        # Delegate to the planner (pure heuristic; also feeds binary info risk_hints).
        from tools.binary import BinaryInfo
        # The planner merges risk_hints + info.risk_hints; pass a minimal info carrying the
        # assessment hints so classification uses both sources.
        info = BinaryInfo(path="", format="", arch="", bits=None, endian=None,
                          entry=None, sha256="", size=0,
                          risk_hints=risk_result.get("risk_hints", []))
        return classify_binary_type(info, risk_result, task=task)

    @staticmethod
    def _fallback_playbook(binary_type: str) -> Workflow:
        try:
            tmpl = playbook_lib.load_template(binary_type)
        except FileNotFoundError:
            tmpl = playbook_lib.load_template("crackme")
        wf = Workflow.from_dict(tmpl["workflow"])
        wf.binary_type = tmpl.get("binary_type", binary_type)
        return wf

    # -------------------------------------------------------- adaptive exec
    def _execute_adaptive(self, wf: Workflow, binary_path: str, ws: Workspace,
                         *, max_adaptations: int = 3) -> None:
        """Run the DAG, adapt on anomalies, and re-run inserted nodes."""
        adapted: set[str] = set()
        for _ in range(max_adaptations + 1):
            self.engine.execute(wf, binary_path, ws, codegen_dir=self.codegen_dir)
            anomaly, node_id = self._find_anomaly(wf, adapted)
            if anomaly is None:
                break
            adapted.add(node_id)
            self.engine.adapt(wf, anomaly=anomaly, anomaly_node_id=node_id, workspace=ws)
        # One final pass to execute any nodes inserted by the last adaptation.
        self.engine.execute(wf, binary_path, ws, codegen_dir=self.codegen_dir)

    @staticmethod
    def _find_anomaly(wf: Workflow, adapted: set[str]):
        for n in wf.nodes:
            if n.id in adapted:
                continue
            # A node that ran but returned an error (or 'vm'/explosion) is an anomaly.
            if n.status == "failed":
                return "node_failed", n.id
            if n.status == "done":
                anomaly = WorkflowEngine.detect_anomaly(n.outputs)
                if anomaly:
                    return anomaly, n.id
        return None, None

    # --------------------------------------------------------- report synth
    @staticmethod
    def _synthesize_report(ws: Workspace, wf: Workflow, risk_level: str, task: str) -> dict:
        total = len(wf.nodes)
        done = sum(1 for n in wf.nodes if n.status == "done")
        failed = sum(1 for n in wf.nodes if n.status == "failed")
        binary = ws.binary
        summary = (f"Analyzed {binary.get('path', '?')} "
                   f"({binary.get('format')}/{binary.get('arch')}, risk {risk_level}); "
                   f"workflow {done}/{total} nodes done, {failed} failed; "
                   f"{len(ws.findings)} findings recorded.")
        return {
            "task": task,
            "binary": binary,
            "risk_level": risk_level,
            "summary": summary,
            "findings": ws.findings,
            "hypotheses": ws.hypotheses,
            "functions": list(ws.functions.values()),
            "vm_spec": ws.vm_spec,
            "workflow": wf.to_dict(),
            "workflow_trace": ws.workflow_trace,
        }
