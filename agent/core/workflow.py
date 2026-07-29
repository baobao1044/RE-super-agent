"""Dynamic workflow engine — the layer the user explicitly asked for: AI designs and
self-modifies the RE workflow.

Architecture (see plan):
- Declarative DAG: nodes (sub-task + specialist + tool + I/O schema + branch condition) and
  edges (from_node -> to_node with a condition: success/fail/always). The Supervisor + LLM
  synthesize the initial DAG; a playbook library provides parametrized templates.
- Execution: topological order; each node dispatches to a specialist (or, for "codegen"
  nodes, the LLM generates Python run inside the Docker sandbox — never on host). Outputs
  flow forward; branch conditions gate which successors run.
- Adaptive loop: when a tool returns an anomaly (function missing, VM detected, symbolic
  explode, node failure), the engine adapts — insert a node, backtrack, switch specialist
  or strategy — recording the reason in the workspace workflow trace.
- Checkpoint/resume: snapshots let a long analysis resume after interruption.
- Playbooks: a successful workflow is saved as a parametrized template keyed by binary type
  (crackme / packed_vm / malware / ctf) and reused for similar binaries.

This module is the pure-logic model + engine; it takes injectable dependencies (an LLM
provider, a sandbox runner, a specialists map) so it is fully testable without Docker or a
cloud LLM. Engine availability is guarded: missing Docker makes codegen nodes degrade to a
static-only error, never to host execution.
"""
from __future__ import annotations

import json
import logging
import re
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from tools.binary import BinaryInfo

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Declarative DAG data model
# ---------------------------------------------------------------------------
@dataclass
class WorkflowNode:
    """One step of the RE workflow DAG."""
    id: str
    sub_task: str
    specialist: str            # malware | static | dynamic | symbolic | deobfuscation | codegen | supervisor
    tool: str | None = None
    inputs: dict = field(default_factory=dict)
    outputs: dict = field(default_factory=dict)
    condition: str | None = None   # success/fail branch condition the node represents
    status: str = "pending"        # pending | running | done | failed | skipped
    error: str | None = None


@dataclass
class WorkflowEdge:
    from_node: str
    to_node: str
    condition: str = "success"      # success | fail | always


@dataclass
class Workflow:
    nodes: list[WorkflowNode] = field(default_factory=list)
    edges: list[WorkflowEdge] = field(default_factory=list)
    binary_type: str = ""           # crackme | packed_vm | malware | ctf | unknown

    @property
    def node_ids(self) -> list[str]:
        return [n.id for n in self.nodes]

    def get_node(self, node_id: str) -> WorkflowNode | None:
        for n in self.nodes:
            if n.id == node_id:
                return n
        return None

    def successors(self, node_id: str, *, condition: str = "success") -> list[WorkflowNode]:
        """Successors reachable via edges whose condition matches (or 'always')."""
        out: list[WorkflowNode] = []
        for e in self.edges:
            if e.from_node != node_id:
                continue
            if e.condition in (condition, "always"):
                tgt = self.get_node(e.to_node)
                if tgt is not None:
                    out.append(tgt)
        return out

    def _predecessors(self, node_id: str) -> list[WorkflowNode]:
        out: list[WorkflowNode] = []
        for e in self.edges:
            if e.to_node == node_id:
                tgt = self.get_node(e.from_node)
                if tgt is not None:
                    out.append(tgt)
        return out

    def validate(self) -> list[str]:
        """Return a list of human-readable structural errors (empty == valid DAG)."""
        errs: list[str] = []
        seen: set[str] = set()
        for n in self.nodes:
            if n.id in seen:
                errs.append(f"duplicate node id: {n.id}")
            seen.add(n.id)
        for e in self.edges:
            if e.from_node not in seen:
                errs.append(f"edge from unknown node: {e.from_node}")
            if e.to_node not in seen:
                errs.append(f"edge to unknown node: {e.to_node}")
        if self._has_cycle():
            errs.append("cycle detected in workflow DAG")
        return errs

    def _adjacency(self) -> dict[str, list[str]]:
        adj: dict[str, list[str]] = {n.id: [] for n in self.nodes}
        for e in self.edges:
            if e.from_node in adj:
                adj[e.from_node].append(e.to_node)
        return adj

    def _has_cycle(self) -> bool:
        # Kahn's algorithm: if not all nodes are removed, a cycle exists.
        adj = self._adjacency()
        indeg = {nid: 0 for nid in adj}
        for src, dsts in adj.items():
            for d in dsts:
                if d in indeg:
                    indeg[d] += 1
        q = deque([nid for nid, deg in indeg.items() if deg == 0])
        removed = 0
        while q:
            cur = q.popleft()
            removed += 1
            for d in adj[cur]:
                if d not in indeg:
                    continue
                indeg[d] -= 1
                if indeg[d] == 0:
                    q.append(d)
        return removed != len(adj)

    def topological_order(self) -> list[WorkflowNode]:
        """Return nodes in dependency order; raise ValueError if a cycle exists."""
        if self._has_cycle():
            raise ValueError("cannot topologically order a cyclic workflow DAG")
        adj = self._adjacency()
        indeg = {nid: 0 for nid in adj}
        for src, dsts in adj.items():
            for d in dsts:
                indeg[d] += 1
        # Stable order: preserve insertion order among ready nodes.
        order: list[WorkflowNode] = []
        by_id = {n.id: n for n in self.nodes}
        remaining = set(adj)
        while remaining:
            ready = [nid for nid in self.node_ids if nid in remaining and indeg[nid] == 0]
            if not ready:
                break
            for nid in ready:
                order.append(by_id[nid])
                remaining.discard(nid)
                for d in adj[nid]:
                    indeg[d] -= 1
        return order

    def to_dict(self) -> dict:
        return {
            "binary_type": self.binary_type,
            "nodes": [
                {"id": n.id, "sub_task": n.sub_task, "specialist": n.specialist,
                 "tool": n.tool, "inputs": n.inputs, "outputs": n.outputs,
                 "condition": n.condition, "status": n.status, "error": n.error}
                for n in self.nodes
            ],
            "edges": [{"from_node": e.from_node, "to_node": e.to_node,
                       "condition": e.condition} for e in self.edges],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Workflow":
        nodes = [WorkflowNode(
            id=n["id"], sub_task=n["sub_task"], specialist=n["specialist"],
            tool=n.get("tool"), inputs=n.get("inputs", {}),
            outputs=n.get("outputs", {}), condition=n.get("condition"),
            status=n.get("status", "pending"), error=n.get("error"),
        ) for n in d.get("nodes", [])]
        edges = [WorkflowEdge(
            from_node=e["from_node"], to_node=e["to_node"],
            condition=e.get("condition", "success"),
        ) for e in d.get("edges", [])]
        return cls(nodes=nodes, edges=edges, binary_type=d.get("binary_type", ""))


# ---------------------------------------------------------------------------
# Workflow engine
# ---------------------------------------------------------------------------
_SYNTH_SYSTEM_PROMPT = """You are the workflow designer for a reverse-engineering super
agent. Given a binary + task, design a declarative DAG workflow as JSON ONLY (no prose).
Available specialists: malware (risk_scan/capa/yara/strings), static (list_functions/
decompile/disassemble/xrefs/strings), dynamic (spawn/attach/hook/anti_analysis), symbolic
(angr/constraint solve/flag extract), deobfuscation (vm_lifter/trace/reconstruct/
hybrid_solve), codegen (LLM-generated Python run in a Docker sandbox — for complex custom
reasoning like VM handler lifting scripts).

Output schema (JSON, no markdown fences):
{
  "binary_type": "crackme|packed_vm|malware|ctf|unknown",
  "nodes": [{"id": "n1", "sub_task": "...", "specialist": "...", "tool": "...",
             "condition": "success|fail|always"}],
  "edges": [{"from_node": "n1", "to_node": "n2", "condition": "success|fail|always"}]
}
Rules: node ids unique; edges reference existing nodes; no cycles; first node should be a
risk scan. Be concise and complete."""


def _extract_json(text: str) -> str:
    """Strip markdown code fences if present and return the JSON body."""
    if not text:
        return ""
    t = text.strip()
    # Remove ```json ... ``` or ``` ... ``` fences.
    fence = re.search(r"```(?:json)?\s*(.*?)```", t, re.DOTALL | re.IGNORECASE)
    if fence:
        t = fence.group(1).strip()
    return t


def _parse_dag_json(text: str) -> Workflow | None:
    """Parse the LLM's JSON DAG text into a Workflow; None on malformed JSON."""
    body = _extract_json(text)
    if not body:
        return None
    try:
        d = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(d, dict) or "nodes" not in d:
        return None
    try:
        return Workflow.from_dict(d)
    except (KeyError, TypeError):
        return None


class WorkflowEngine:
    """Synthesizes, executes, and adapts the RE workflow DAG.

    Dependencies are injected so the engine is testable without Docker or a cloud LLM:
    - provider: an LLMProvider (complete(messages, tools)).
    - sandbox: a sandbox runner (run_codegen(script_path, image, input_path, timeout)) or
      None; codegen nodes degrade to a static-only error when the sandbox is unavailable.
    - specialists: {specialist_name: Specialisinstance} dispatched by execute().
    - playbooks_dir: directory for playbook save/load (Stage 8g).
    """

    def __init__(self, *, provider, sandbox=None, specialists: dict | None = None,
                 playbooks_dir=None):
        self.provider = provider
        self.sandbox = sandbox
        self.specialists = specialists or {}
        self.playbooks_dir = playbooks_dir

    # ------------------------------------------------------------------ synth
    def synthesize(self, *, task: str, binary_info: BinaryInfo,
                   risk_assessment: dict | None = None,
                   fallback_playbook: Workflow | None = None,
                   max_retries: int = 2) -> Workflow:
        """Ask the LLM to design the initial DAG; re-prompt on malformed/invalid output.

        Falls back to `fallback_playbook` (if given) when the LLM exhausts retries.
        """
        sys_prompt = _SYNTH_SYSTEM_PROMPT
        user_prompt = self._build_synth_prompt(task, binary_info, risk_assessment)
        messages = [
            {"role": "system", "content": sys_prompt},
            {"role": "user", "content": user_prompt},
        ]
        last_errors: list[str] = []
        for attempt in range(max_retries + 1):
            resp = self.provider.complete(messages=messages, tools=None)
            wf = _parse_dag_json(resp.content or "")
            if wf is None:
                last_errors = ["malformed JSON (not a parseable DAG)"]
                messages.append({"role": "assistant", "content": resp.content or ""})
                messages.append({"role": "user", "content":
                    f"That was not valid JSON DAG. Errors: {last_errors}. "
                    "Respond with JSON ONLY matching the schema."})
                continue
            errs = wf.validate()
            if errs:
                last_errors = errs
                messages.append({"role": "assistant", "content": resp.content or ""})
                messages.append({"role": "user", "content":
                    f"That DAG is structurally invalid: {errs}. "
                    "Fix and respond with JSON ONLY."})
                continue
            return wf
        # LLM exhausted retries — fall back to the supplied playbook template if any.
        if fallback_playbook is not None:
            log.warning("workflow synth fell back to playbook after %d retries: %s",
                        max_retries, last_errors)
            return fallback_playbook
        raise ValueError(f"could not synthesize a valid workflow: {last_errors}")

    @staticmethod
    def _build_synth_prompt(task: str, binary_info: BinaryInfo,
                            risk_assessment: dict | None) -> str:
        parts = [f"Task: {task}",
                 f"Binary: format={binary_info.format} arch={binary_info.arch} "
                 f"bits={binary_info.bits} entry={binary_info.entry}",
                 f"Risk hints: {binary_info.risk_hints}"]
        if risk_assessment:
            parts.append(f"Risk assessment: level={risk_assessment.get('risk_level')} "
                         f"reasons={risk_assessment.get('reasons')}")
        parts.append("Design the workflow DAG as JSON ONLY.")
        return "\n".join(parts)

    # ---------------------------------------------------------- checkpoint
    def checkpoint_save(self, wf: Workflow, ws, path) -> None:
        """Persist the full workflow + workspace state to a JSON file for resume.

        An interrupted node (status='running') is recorded as 'running' here and reset to
        'pending' on load so resume re-runs it.
        """
        path = Path(path)
        payload = {
            "binary_type": wf.binary_type,
            "workflow": wf.to_dict(),
            "workspace": ws.to_dict(),
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    @staticmethod
    def checkpoint_load(path) -> tuple[Workflow, "Workspace"]:
        """Load a checkpoint into a fresh Workflow + Workspace, ready to resume.

        Resets any 'running' node to 'pending' (interrupted mid-run) and leaves 'done' nodes
        intact so resume skips them. Returns (workflow, workspace).
        """
        from agent.state.workspace import Workspace  # local import to avoid cycle
        path = Path(path)
        d = json.loads(path.read_text(encoding="utf-8"))
        wf = Workflow.from_dict(d["workflow"])
        wf.binary_type = d.get("binary_type", wf.binary_type)
        for n in wf.nodes:
            if n.status == "running":
                n.status = "pending"
        ws = Workspace.from_dict(d["workspace"])
        return wf, ws

    # ------------------------------------------------------------------ execute
    def execute(self, wf: Workflow, binary_path, workspace, *,
                max_node_retries: int = 0, codegen_dir=None) -> Workflow:
        """Run the DAG in topological order, dispatching each node to its specialist.

        Branch conditions gate successors: a 'success' edge runs only if the predecessor
        succeeded; a 'fail' edge only if it failed; an 'always' edge runs regardless of
        success/failure (but not if the predecessor was skipped). Already-'done' nodes are
        skipped (resume support). 'codegen' specialist nodes ask the LLM for a Python
        snippet, persist it to `codegen_dir`, and run it inside the sandbox (never host).
        Each step is recorded in the workspace workflow trace.
        Returns the mutated workflow (node statuses/outputs).
        """
        status: dict[str, str] = {}  # node_id -> done | failed | skipped
        for node in wf.topological_order():
            # Resume: a node already 'done' from a prior partial run is skipped (its
            # outputs stay intact) but counted as satisfied for successor gating.
            if node.status == "done":
                status[node.id] = "done"
                continue
            pred_edges = [e for e in wf.edges if e.to_node == node.id]
            if pred_edges and not self._all_edges_satisfied(wf, pred_edges, status):
                node.status = "skipped"
                status[node.id] = "skipped"
                workspace.record_workflow_step(
                    action="skip_node", reason="precondition not met",
                    extra={"node": node.id, "specialist": node.specialist})
                continue
            if node.specialist == "codegen":
                result = self._run_codegen_node(node, str(binary_path), workspace,
                                               codegen_dir=codegen_dir)
            else:
                result = self._dispatch(node, str(binary_path), workspace, max_node_retries)
            if result is None or (isinstance(result, dict) and result.get("error")):
                node.status = "failed"
                node.error = (result.get("error") if isinstance(result, dict) else None) \
                    or "node produced no result"
                status[node.id] = "failed"
            else:
                node.status = "done"
                node.outputs = result if isinstance(result, dict) else {"result": result}
                status[node.id] = "done"
                if node.specialist == "codegen":
                    workspace.add_finding(
                        kind="codegen_result",
                        summary=f"code-gen node '{node.id}' produced: {node.outputs}",
                        source="codegen")
            workspace.record_workflow_step(
                action="execute_node", reason=node.sub_task,
                extra={"node": node.id, "specialist": node.specialist,
                       "status": node.status})
        return wf

    @staticmethod
    def _all_edges_satisfied(wf: Workflow, pred_edges: list[WorkflowEdge],
                             status: dict[str, str]) -> bool:
        """True iff every predecessor ran AND its status matches the edge condition."""
        for e in pred_edges:
            ps = status.get(e.from_node)
            if ps is None or ps == "skipped" or ps == "running":
                return False  # predecessor didn't run (or was skipped)
            cond = e.condition
            if cond == "always":
                continue
            if cond == "success" and ps != "done":
                return False
            if cond == "fail" and ps != "failed":
                return False
        return True

    def _dispatch(self, node: WorkflowNode, binary_path: str, workspace,
                  max_node_retries: int):
        """Dispatch a node to its specialist; return the result dict or None on error."""
        specialist = self.specialists.get(node.specialist)
        if specialist is None:
            return {"error": f"no specialist registered for '{node.specialist}'"}
        attempts = max_node_retries + 1
        last_exc: Exception | None = None
        for _ in range(attempts):
            try:
                return specialist.run(task=node.sub_task, binary_path=binary_path,
                                      workspace=workspace)
            except Exception as exc:  # noqa: BLE001 — engine must not crash on a node
                last_exc = exc
        return {"error": f"{type(last_exc).__name__}: {last_exc}"}

    # ---------------------------------------------------------- codegen node
    _CODEGEN_SYSTEM_PROMPT = """You are a code generator for a reverse-engineering super
agent. Write a self-contained Python snippet that produces a result as JSON printed to
stdout (use json.dumps). The snippet runs inside a sandboxed container (no network, no
host access). Output Python code ONLY — no markdown fences, no prose."""

    def _run_codegen_node(self, node: WorkflowNode, binary_path: str, workspace,
                          *, codegen_dir=None, max_retries: int = 1) -> dict:
        """Ask the LLM for a Python snippet, persist it to disk, run it in the sandbox.

        NEVER evals the snippet on the host — it is written to a file under codegen_dir
        and handed to the sandbox runner. Degrades to a failed error when the sandbox is
        unavailable or returns a non-OK result.
        """
        if self.sandbox is None:
            return {"error": "codegen node requires a sandbox (Docker unavailable) — "
                             "degrading to static-only; refusing host execution"}
        if codegen_dir is None:
            from tempfile import gettempdir
            codegen_dir = Path(gettempdir())
        else:
            codegen_dir = Path(codegen_dir)
        messages = [
            {"role": "system", "content": self._CODEGEN_SYSTEM_PROMPT},
            {"role": "user", "content": f"Task: {node.sub_task}\n"
                                        f"Binary path (sandbox-visible read-only): {binary_path}"},
        ]
        for attempt in range(max_retries + 1):
            resp = self.provider.complete(messages=messages, tools=None)
            snippet = (resp.content or "").strip()
            # strip markdown fences if the model added them despite instructions
            fence = re.search(r"```(?:python)?\s*(.*?)```", snippet, re.DOTALL | re.IGNORECASE)
            if fence:
                snippet = fence.group(1).strip()
            if not snippet:
                messages.append({"role": "assistant", "content": resp.content or ""})
                messages.append({"role": "user", "content":
                    "That snippet was empty. Write Python code ONLY that prints JSON to stdout."})
                continue
            script_path = codegen_dir / f"codegen_{node.id}.py"
            script_path.write_text(snippet, encoding="utf-8")
            try:
                result = self.sandbox.run_codegen(script_path, image="re-agent:full")
            except Exception as exc:  # noqa: BLE001 — SandboxUnavailableError or daemon
                return {"error": f"sandbox unavailable: {exc}"}
            if not result.get("ok", True):
                return {"error": result.get("error", "snippet failed in sandbox")}
            out = result.get("result")
            if isinstance(out, dict):
                return out
            return {"result": out}
        return {"error": "LLM produced no runnable snippet after retries"}

    # --------------------------------------------------------- adaptive loop
    @staticmethod
    def detect_anomaly(node_result: dict) -> str | None:
        """Pure heuristic over a node's result dict. Returns the anomaly kind or None.

        Kinds: vm_detected | symbolic_explode | node_failed. The engine uses this to
        decide whether to trigger self-modification without waiting for the LLM.
        """
        if not isinstance(node_result, dict):
            return None
        if node_result.get("error"):
            return "node_failed"
        if node_result.get("vm") is True:
            return "vm_detected"
        obf = node_result.get("obfuscated")
        if isinstance(obf, str) and "VM" in obf.upper():
            return "vm_detected"
        if node_result.get("path_explosion") is True:
            return "symbolic_explode"
        states = node_result.get("states_explored")
        if isinstance(states, (int, float)) and states >= 1_000_000:
            return "symbolic_explode"
        return None

    def adapt(self, wf: Workflow, *, anomaly: str, anomaly_node_id: str,
              workspace, max_retries: int = 2) -> Workflow:
        """Ask the LLM for a structural patch to the DAG, validate it, and apply it.

        Patch schema (JSON):
          {"action": "insert_after|replace_node|switch_specialist|backtrack",
           "node_id": "...", "new_node": {id,sub_task,specialist,tool?},
           "specialist": "...", "reason": "..."}
        The reason is recorded in the workspace workflow trace for observability.
        Re-prompts on malformed/invalid patch up to max_retries.
        """
        messages = [
            {"role": "system", "content": _ADAPT_SYSTEM_PROMPT},
            {"role": "user", "content": self._build_adapt_prompt(wf, anomaly, anomaly_node_id)},
        ]
        last_err = "no response"
        for _ in range(max_retries + 1):
            resp = self.provider.complete(messages=messages, tools=None)
            patch = _parse_patch_json(resp.content or "")
            if patch is None:
                last_err = "malformed patch JSON"
                messages.append({"role": "assistant", "content": resp.content or ""})
                messages.append({"role": "user", "content":
                    f"That was not a valid patch JSON. Error: {last_err}. "
                    "Respond with JSON ONLY."})
                continue
            verr = _validate_patch(wf, patch)
            if verr:
                last_err = verr
                messages.append({"role": "assistant", "content": resp.content or ""})
                messages.append({"role": "user", "content":
                    f"Patch invalid: {verr}. Fix and respond with JSON ONLY."})
                continue
            self._apply_patch(wf, patch)
            workspace.record_workflow_step(
                action="adapt", reason=patch.get("reason", anomaly),
                extra={"anomaly": anomaly, "node": anomaly_node_id,
                       "patch_action": patch["action"]})
            return wf
        log.warning("workflow adapt exhausted retries: %s", last_err)
        workspace.record_workflow_step(
            action="adapt_failed", reason=last_err,
            extra={"anomaly": anomaly, "node": anomaly_node_id})
        return wf

    @staticmethod
    def _build_adapt_prompt(wf: Workflow, anomaly: str, anomaly_node_id: str) -> str:
        return (f"Anomaly detected: {anomaly} at node {anomaly_node_id}.\n"
                f"Current DAG:\n{json.dumps(wf.to_dict(), indent=2)}\n"
                "Propose ONE structural patch as JSON ONLY to fix the workflow.")

    @staticmethod
    def _apply_patch(wf: Workflow, patch: dict):
        action = patch["action"]
        nid = patch["node_id"]
        if action == "switch_specialist":
            n = wf.get_node(nid)
            n.specialist = patch["specialist"]
            n.status = "pending"
            n.error = None
            return
        if action == "backtrack":
            n = wf.get_node(nid)
            n.status = "pending"
            n.error = None
            return
        if action == "insert_after":
            nn = patch["new_node"]
            new = WorkflowNode(id=nn["id"], sub_task=nn["sub_task"],
                              specialist=nn["specialist"], tool=nn.get("tool"))
            wf.nodes.append(new)
            # rewire: edges from nid -> X become new -> X; add nid -> new (success)
            for e in list(wf.edges):
                if e.from_node == nid:
                    e.from_node = new.id
            wf.edges.append(WorkflowEdge(from_node=nid, to_node=new.id, condition="success"))
            return
        if action == "replace_node":
            nn = patch["new_node"]
            n = wf.get_node(nid)
            n.sub_task = nn["sub_task"]
            n.specialist = nn["specialist"]
            n.tool = nn.get("tool")
            n.status = "pending"
            n.error = None
            return

    # ---------------------------------------------------------- playbooks
    def save_playbook(self, wf: Workflow, name: str) -> Path:
        """Save a workflow as a status-agnostic template named by binary type.

        Strips per-node outputs/status/errors so the template is reusable. Writes to
        <playbooks_dir>/<name>.json and returns the path.
        """
        if self.playbooks_dir is None:
            raise ValueError("no playbooks_dir configured")
        d = self.playbooks_dir
        d = Path(d)
        d.mkdir(parents=True, exist_ok=True)
        template = wf.to_dict()
        for n in template["nodes"]:
            n["status"] = "pending"
            n["outputs"] = {}
            n["error"] = None
        payload = {"binary_type": wf.binary_type, "workflow": template}
        out = d / f"{name}.json"
        out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return out

    def load_playbook(self, name: str) -> Workflow:
        """Rebuild a fresh Workflow from a saved template (all nodes 'pending')."""
        if self.playbooks_dir is None:
            raise FileNotFoundError("no playbooks_dir configured")
        p = Path(self.playbooks_dir) / f"{name}.json"
        if not p.exists():
            raise FileNotFoundError(f"no playbook '{name}' in {self.playbooks_dir}")
        d = json.loads(p.read_text(encoding="utf-8"))
        wf = Workflow.from_dict(d["workflow"])
        wf.binary_type = d.get("binary_type", wf.binary_type)
        for n in wf.nodes:
            n.status = "pending"
            n.outputs = {}
            n.error = None
        return wf

    def list_playbooks(self) -> list[str]:
        """Return the available playbook names (without .json suffix)."""
        if self.playbooks_dir is None:
            return []
        d = Path(self.playbooks_dir)
        if not d.exists():
            return []
        return sorted(p.stem for p in d.glob("*.json"))


_ADAPT_SYSTEM_PROMPT = """You are the workflow adapter for a reverse-engineering super
agent. When an anomaly (VM detected, symbolic path explosion, node failure) occurs, propose
ONE structural patch to the workflow DAG as JSON ONLY (no prose, no fences).

Patch schema:
{"action": "insert_after|replace_node|switch_specialist|backtrack",
 "node_id": "the node to patch",
 "new_node": {"id": "nx", "sub_task": "...", "specialist": "...", "tool": "..."},
 "specialist": "alternative specialist (for switch_specialist)",
 "reason": "why this patch helps"}
Rules:
- insert_after: insert new_node between node_id and its successors (devirtualize before
  symbolic solve, add trace-narrowing before a re-run, etc.). Provide new_node.
- replace_node: replace node_id's task/specialist/tool with new_node's (keep the id).
- switch_specialist: change node_id's specialist; reset it to re-run. Provide specialist.
- backtrack: reset node_id to re-run as-is (e.g. transient failure).
Respond with JSON ONLY."""


def _parse_patch_json(text: str) -> dict | None:
    body = _extract_json(text)
    if not body:
        return None
    try:
        d = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(d, dict) or "action" not in d or "node_id" not in d:
        return None
    return d


def _validate_patch(wf: Workflow, patch: dict) -> str | None:
    action = patch.get("action")
    nid = patch.get("node_id")
    valid_actions = {"insert_after", "replace_node", "switch_specialist", "backtrack"}
    if action not in valid_actions:
        return f"unknown action: {action}"
    if wf.get_node(nid) is None:
        return f"node_id {nid} does not exist"
    if action in ("insert_after", "replace_node"):
        nn = patch.get("new_node")
        if not isinstance(nn, dict) or "id" not in nn or "sub_task" not in nn \
                or "specialist" not in nn:
            return "new_node must have id, sub_task, specialist"
        if action == "insert_after" and wf.get_node(nn["id"]) is not None:
            return f"new_node id {nn['id']} already exists"
    if action == "switch_specialist" and not patch.get("specialist"):
        return "switch_specialist requires a specialist"
    return None
