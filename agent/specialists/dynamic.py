"""Dynamic analysis specialist — runs anti-analysis detection first, then a ReAct loop
over the dynamic tools, and writes findings to the workspace.

CRITICAL: a GatingRegistry wraps the tool registry so that spawn/attach are intercepted
by the safety gate. If safety.decide() denies execution (HIGH risk or no sandbox), the
real spawn/attach are NEVER called — the specialist reports a refused dynamic run instead
of executing an untrusted binary. This is the enforcement point for "never execute on host
/ never run HIGH-risk binaries".
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Callable

from agent.core import safety
from agent.core.react_loop import react_loop
from agent.state.workspace import Workspace
from tools.binary import analyze

log = logging.getLogger(__name__)

DEFAULT_SYSTEM_PROMPT = """You are the dynamic analysis specialist of a reverse-engineering
super agent. You RUN the binary (in a sandboxed environment) to observe its behavior.

Available tools:
- detect_anti_analysis(path): scan for anti-debug/anti-VM/TLS indicators (static, no exec).
- recommend_handling(anti_hints): get recommended handling steps before execution.
- spawn(path, args): spawn the process for instrumentation (frida).
- run_restricted(args, timeout, risk_level, allow_host_fallback): run a runnable target
  (e.g. a protected Python script) under weak-isolation restricted subprocess. Refuses
  HIGH risk. Only set allow_host_fallback=true when Docker is unavailable AND the user
  explicitly accepted the weak-isolation risk. Captures stdout/stderr/exit_code.
- attach(target): attach to a running process.
- list_processes(): list running processes.
- set_breakpoint(session, location): set a breakpoint.
- hook_function(session, addr, script): hook a function with a frida script.
- read_memory(session, addr, size): read process memory.
- get_regs(session): read register values.

SAFETY RULES (non-negotiable):
1. ALWAYS call detect_anti_analysis FIRST, before any spawn/attach/run_restricted.
2. If the safety gate refuses execution (HIGH risk or no sandbox), you MUST NOT spawn.
   Report that dynamic execution was refused and rely on static/symbolic results instead.
3. Apply recommended anti-analysis handling (patch/hide/emulate) before spawning.
4. Never attempt to execute a binary on the host directly; spawn goes through the sandbox.
5. For run_restricted: never set allow_host_fallback=true unless the user has opted in;
   never run a HIGH-risk target; use a short timeout; report captured output, not your guess.
Be concise. State whether execution was permitted and what behavior you observed.
"""

# Tools that perform real execution / attachment — gated by the safety decision.
# run_restricted is a weak-isolation fallback (subprocess) for runnable targets
# when Docker is unavailable; it carries its own opt-in flag, but we still gate it
# here so HIGH-risk targets can never reach it.
_EXEC_TOOLS = {"spawn", "attach", "run_restricted"}


class _GatingRegistry:
    """Wraps a tool registry; gates spawn/attach behind the safety decision.

    If the safety gate denies execution, exec tools return a refused error instead of
    forwarding to the real backend (so the untrusted binary is never run).
    """

    def __init__(self, inner, *, binary_path, workspace, risk_assessment=None):
        self._inner = inner
        self._binary_path = str(binary_path)
        self._workspace = workspace
        self._risk_assessment = risk_assessment
        self.captured: dict[str, dict] = {}
        self._decision = None  # cached safety decision

    def execute(self, name: str, arguments: dict):
        if name in _EXEC_TOOLS:
            if not self._allowed():
                reason = self._decision.reason if self._decision else "safety gate denied"
                refused = {"available": False, "refused": True,
                           "reason": f"dynamic execution refused: {reason}"}
                # Record the refusal so the specialist's executed/refused flags detect it.
                if name in ("spawn", "attach"):
                    self.captured[name] = refused
                return refused
        result = self._inner[name](arguments) if name in self._inner else {"error": f"unknown tool {name}"}
        if name in ("detect_anti_analysis", "recommend_handling", "spawn", "get_regs", "run_restricted"):
            self.captured[name] = result
        return result

    def _allowed(self) -> bool:
        try:
            info = analyze(self._binary_path)
        except Exception as exc:  # noqa: BLE001
            self._decision = type("D", (), {"reason": str(exc)})()
            return False
        self._decision = safety.decide(info, risk_assessment=self._risk_assessment)
        return bool(self._decision.allowed)


class DynamicSpecialist:
    def __init__(self, provider, tools_registry, system_prompt: str = DEFAULT_SYSTEM_PROMPT):
        self.provider = provider
        self.tools_registry = tools_registry
        self.system_prompt = system_prompt

    def run(self, *, task: str, binary_path: str | Path, workspace: Workspace,
            risk_assessment: dict | None = None) -> dict:
        path = str(binary_path)
        gate = _GatingRegistry(self.tools_registry, binary_path=path,
                               workspace=workspace, risk_assessment=risk_assessment)

        tools = [
            {"type": "function", "function": {"name": "detect_anti_analysis",
              "description": "Scan the binary for anti-analysis indicators.",
              "parameters": {"type": "object", "properties": {}}}},
            {"type": "function", "function": {"name": "recommend_handling",
              "description": "Get recommended handling for detected anti-analysis hints.",
              "parameters": {"type": "object", "properties": {
                  "anti_hints": {"type": "array", "items": {"type": "string"}}}}}},
            {"type": "function", "function": {"name": "spawn",
              "description": "Spawn the process for instrumentation.",
              "parameters": {"type": "object", "properties": {"args": {"type": "array"}}}}},
            {"type": "function", "function": {"name": "run_restricted",
              "description": "Run a runnable target (e.g. a protected Python script) under "
                            "weak-isolation restricted subprocess. Refuses HIGH risk. Only set "
                            "allow_host_fallback=true when Docker is unavailable and the user "
                            "opted into the weak-isolation risk. Captures stdout/stderr/exit_code.",
              "parameters": {"type": "object", "properties": {
                  "args": {"type": "array", "items": {"type": "string"}},
                  "timeout": {"type": "integer"},
                  "risk_level": {"type": "string"},
                  "allow_host_fallback": {"type": "boolean"}}}}},
            {"type": "function", "function": {"name": "set_breakpoint",
              "description": "Set a breakpoint.",
              "parameters": {"type": "object", "properties": {
                  "session": {"type": "string"}, "location": {"type": "string"}}}}},
            {"type": "function", "function": {"name": "get_regs",
              "description": "Read register values.",
              "parameters": {"type": "object", "properties": {"session": {"type": "string"}}}}},
        ]

        result = react_loop(
            provider=self.provider,
            registry=gate,
            messages=[{"role": "user", "content": f"{task}\nBinary path: {path}"}],
            tools=tools,
            system=self.system_prompt,
        )

        # Assemble report from captured tool results.
        anti_hints: list[str] = []
        if "detect_anti_analysis" in gate.captured:
            anti_hints = gate.captured["detect_anti_analysis"].get("hints", [])
            if anti_hints:
                workspace.add_finding(
                    kind="anti_analysis",
                    summary=f"Detected anti-analysis: {', '.join(anti_hints)}",
                    source="dynamic",
                )

        executed = "spawn" in gate.captured and not gate.captured["spawn"].get("refused")
        refused = "spawn" in gate.captured and gate.captured["spawn"].get("refused")
        reason = gate.captured.get("spawn", {}).get("reason", "") if refused else ""

        restricted_run = gate.captured.get("run_restricted")
        restricted_ok = (isinstance(restricted_run, dict)
                         and restricted_run.get("available")
                         and restricted_run.get("ok"))
        if restricted_ok:
            workspace.add_finding(
                kind="restricted_exec",
                summary=f"Ran target under restricted subprocess: exit_code="
                        f"{restricted_run.get('exit_code')}, timed_out="
                        f"{restricted_run.get('timed_out')}, stdout="
                        f"{(restricted_run.get('stdout') or '')[:80]!r}",
                source="dynamic",
            )

        return {
            "narrative": result.final_text,
            "anti_hints": anti_hints,
            "executed": executed,
            "refused": refused,
            "reason": reason,
            "restricted_run": restricted_run,
            "steps": [{"tool": s.tool_name, "error": s.tool_error} for s in result.steps],
            "truncated": result.truncated,
        }
