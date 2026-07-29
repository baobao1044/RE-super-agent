"""Deobfuscation specialist — lifts VM handlers, builds a VM spec in the workspace, and
devirtualizes packed/VM-based obfuscators via the trace-driven hybrid.

Key behaviors:
- lift_vm_handler / build_vm_spec calls populate workspace.vm_spec (shared with static/
  symbolic specialists so they can read the recovered semantics).
- disassemble_vm_bytecode auto-injects the workspace's current VM spec so the tool can
  label the bytecode (the LLM only passes the raw bytecode).
- The specialist accumulates lifted opcodes and writes a finding summarizing the spec.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Callable

from agent.core.react_loop import react_loop
from agent.state.workspace import Workspace

log = logging.getLogger(__name__)

DEFAULT_SYSTEM_PROMPT = """You are the deobfuscation / devirtualization specialist of a
reverse-engineering super agent. You defeat VM-based obfuscation (VMProtect/Themida/custom
VMs) where symbolic execution alone explodes.

Available tools:
- load_target(path): load the binary into Qiling for safe emulation (may be unavailable).
- trace_execution(path, max_steps): emulate and return a (pc, mnemonic) trace.
- lift_vm_handler(dispatch_addr, opcode, name, effects): record one VM opcode's semantics
  into the shared VM spec (stored in the workspace).
- build_vm_spec(dispatch_addr, handlers): build a full VM spec from multiple handlers.
- disassemble_vm_bytecode(bytecode): disassemble VM bytecode using the CURRENT workspace
  VM spec (you only pass the raw bytecode; the spec is injected automatically).
- reconstruct_native(trace, dedup): reconstruct native ops from a concrete trace.
- hybrid_solve(trace, predicate_str, input_length, alphabet_start, alphabet_end):
  trace-narrowed constraint solving (pure solver fallback).

Strategy (hybrid, avoids path explosion):
1. Identify the VM dispatcher and handlers via static findings.
2. lift_vm_handler for each handler to build the VM spec.
3. disassemble_vm_bytecode to read the encoded program.
4. If Qiling is available, trace_execution for a concrete path; reconstruct_native to
   recover the real executed code; hybrid_solve on the narrow exposed slice.
5. Write the VM spec to the workspace so static/symbolic specialists can consume it.
Be concise. State how many opcodes you lifted and what the devirtualized code does.
"""


class _WorkspaceRegistry:
    """Wraps the deobf tool registry; injects the workspace VM spec into disasm calls and
    captures lifted specs / disassembly / traces into the workspace + report."""

    def __init__(self, inner: dict[str, Callable], workspace: Workspace):
        self._inner = inner
        self._ws = workspace
        self.captured: dict[str, object] = {}
        self.lifted = 0
        self.disassembly: list[dict] = []
        self.reconstructed: list[dict] = []

    def execute(self, name: str, arguments: dict):
        if name == "lift_vm_handler":
            res = self._inner[name](arguments) if name in self._inner else {"error": "unknown"}
            # Merge the returned spec into the workspace VM spec.
            self._merge_spec(res)
            self.lifted += 1
            return res
        if name == "build_vm_spec":
            res = self._inner[name](arguments) if name in self._inner else {"error": "unknown"}
            self._ws.set_vm_spec(res)
            return res
        if name == "disassemble_vm_bytecode":
            # Inject the current workspace VM spec so the tool can label the bytecode.
            args = dict(arguments)
            if "spec" not in args or not args.get("spec"):
                args["spec"] = self._ws.vm_spec or {"dispatch_addr": 0, "opcodes": {}}
            res = self._inner[name](args) if name in self._inner else []
            if isinstance(res, list):
                self.disassembly = res
            return res
        if name == "reconstruct_native":
            res = self._inner[name](arguments) if name in self._inner else []
            if isinstance(res, list):
                self.reconstructed = res
            return res
        return self._inner[name](arguments) if name in self._inner else {"error": f"unknown tool {name}"}

    def _merge_spec(self, spec: dict):
        if not isinstance(spec, dict) or "opcodes" not in spec:
            return
        current = self._ws.vm_spec
        if not current:
            self._ws.set_vm_spec(spec)
        else:
            current.setdefault("opcodes", {}).update(spec.get("opcodes", {}))
            current.setdefault("handler_table", []).extend(spec.get("handler_table", []))


class DeobfuscationSpecialist:
    def __init__(self, provider, tools_registry, system_prompt: str = DEFAULT_SYSTEM_PROMPT):
        self.provider = provider
        self.tools_registry = tools_registry
        self.system_prompt = system_prompt

    def run(self, *, task: str, binary_path: str | Path, workspace: Workspace) -> dict:
        path = str(binary_path)
        reg = _WorkspaceRegistry(self.tools_registry, workspace)

        tools = [
            {"type": "function", "function": {"name": "lift_vm_handler",
              "description": "Record one VM opcode's semantics into the VM spec.",
              "parameters": {"type": "object", "properties": {
                  "dispatch_addr": {"type": "integer"}, "opcode": {"type": "integer"},
                  "name": {"type": "string"}, "effects": {"type": "string"}}}}},
            {"type": "function", "function": {"name": "disassemble_vm_bytecode",
              "description": "Disassemble VM bytecode using the current workspace VM spec.",
              "parameters": {"type": "object", "properties": {"bytecode": {"type": "string"}}}}},
            {"type": "function", "function": {"name": "reconstruct_native",
              "description": "Reconstruct native ops from a trace.",
              "parameters": {"type": "object", "properties": {
                  "trace": {"type": "array"}, "dedup": {"type": "boolean"}}}}},
            {"type": "function", "function": {"name": "hybrid_solve",
              "description": "Trace-narrowed constraint solve.",
              "parameters": {"type": "object", "properties": {
                  "trace": {"type": "array"}, "predicate_str": {"type": "string"},
                  "input_length": {"type": "integer"},
                  "alphabet_start": {"type": "integer"}, "alphabet_end": {"type": "integer"}}}}},
        ]

        result = react_loop(
            provider=self.provider,
            registry=reg,
            messages=[{"role": "user", "content": f"{task}\nBinary path: {path}"}],
            tools=tools,
            system=self.system_prompt,
        )

        lifted = len(workspace.vm_spec.get("opcodes", {})) if workspace.vm_spec else 0
        if lifted:
            workspace.add_finding(
                kind="vm_spec",
                summary=f"Built VM spec with {lifted} lifted opcodes at dispatch "
                        f"{hex(workspace.vm_spec.get('dispatch_addr', 0))}",
                source="deobfuscation",
            )

        return {
            "narrative": result.final_text,
            "lifted_opcodes": lifted,
            "disassembly": reg.disassembly,
            "reconstructed": reg.reconstructed,
            "vm_spec": workspace.vm_spec,
            "steps": [{"tool": s.tool_name, "error": s.tool_error} for s in result.steps],
            "truncated": result.truncated,
        }
