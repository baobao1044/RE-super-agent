"""Symbolic analysis specialist — runs a ReAct loop over the symbolic MCP tools and
writes recovered flags / satisfying inputs into the workspace.

Captures the structured results from extract_flag / find_input_satisfying and records
them as workspace findings so the supervisor can synthesize them into the final report.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Callable

from agent.core.react_loop import react_loop
from agent.state.workspace import Workspace

log = logging.getLogger(__name__)

DEFAULT_SYSTEM_PROMPT = """You are the symbolic analysis specialist of a reverse-engineering
super agent. You use symbolic execution / constraint solving to recover inputs and flags
WITHOUT running the binary (pure reasoning over constraints).

Available tools:
- load_project(path): load the binary into angr (may be unavailable).
- explore_to(path, target_addr, avoid): symbolically reach a target address.
- find_input_satisfying(predicate_str, input_length, alphabet_start, alphabet_end):
  find bytes of input_length satisfying a lambda predicate (pure solver fallback).
- extract_flag(predicate_str, expected_len, alphabet_start, alphabet_end):
  find bytes of expected_len satisfying a flag predicate; returns the flag string.
- get_state_info(path): CFG function count + entry via angr.

Predicates are lambda expressions over a bytes argument x, e.g.
  "lambda x: x == b'CAT'"
For CTF flag-checkers, infer the secret comparison from static analysis and encode it.

Rules:
1. Prefer extract_flag / find_input_satisfying with a predicate derived from static findings.
2. Report the recovered flag or input exactly. Write it to the workspace.
3. If angr is unavailable, the pure solver handles short secrets; for long ones, note the
   limitation and suggest the workflow engine's trace-driven hybrid deobfuscation.
Be concise. State whether a solution was found and what it is.
"""


class _CapturingRegistry:
    def __init__(self, inner: dict[str, Callable]):
        self._inner = inner
        self.captured: dict[str, dict] = {}

    def execute(self, name: str, arguments: dict):
        result = self._inner[name](arguments) if name in self._inner else {"error": f"unknown tool {name}"}
        if name in ("extract_flag", "find_input_satisfying", "explore_to"):
            self.captured[name] = result
        return result


class SymbolicSpecialist:
    def __init__(self, provider, tools_registry, system_prompt: str = DEFAULT_SYSTEM_PROMPT):
        self.provider = provider
        self.tools_registry = tools_registry
        self.system_prompt = system_prompt

    def run(self, *, task: str, binary_path: str | Path, workspace: Workspace) -> dict:
        path = str(binary_path)
        cap = _CapturingRegistry(self.tools_registry)

        tools = [
            {"type": "function", "function": {"name": "extract_flag",
              "description": "Find a flag (bytes of expected_len) satisfying a predicate.",
              "parameters": {"type": "object", "properties": {
                  "predicate_str": {"type": "string"},
                  "expected_len": {"type": "integer"},
                  "alphabet_start": {"type": "integer"},
                  "alphabet_end": {"type": "integer"}}}}},
            {"type": "function", "function": {"name": "find_input_satisfying",
              "description": "Find input satisfying a predicate.",
              "parameters": {"type": "object", "properties": {
                  "predicate_str": {"type": "string"},
                  "input_length": {"type": "integer"},
                  "alphabet_start": {"type": "integer"},
                  "alphabet_end": {"type": "integer"}}}}},
            {"type": "function", "function": {"name": "explore_to",
              "description": "Symbolically explore to a target address.",
              "parameters": {"type": "object", "properties": {
                  "target_addr": {"type": "integer"}, "avoid": {"type": "array", "items": {"type": "integer"}}}}}},
        ]

        result = react_loop(
            provider=self.provider,
            registry=cap,
            messages=[{"role": "user", "content": f"{task}\nBinary path: {path}"}],
            tools=tools,
            system=self.system_prompt,
        )

        report: dict = {
            "narrative": result.final_text,
            "found": False,
            "flag": None,
            "input": None,
            "steps": [{"tool": s.tool_name, "error": s.tool_error} for s in result.steps],
            "truncated": result.truncated,
        }

        if "extract_flag" in cap.captured:
            fr = cap.captured["extract_flag"]
            report["found"] = bool(fr.get("found"))
            report["flag"] = fr.get("flag")
            if report["found"] and report["flag"]:
                workspace.add_finding(
                    kind="flag",
                    summary=f"Recovered flag: {report['flag']}",
                    source="symbolic",
                    confidence=1.0,
                )

        if "find_input_satisfying" in cap.captured:
            sr = cap.captured["find_input_satisfying"]
            report["found"] = report["found"] or bool(sr.get("found"))
            report["input"] = sr.get("input")
            if sr.get("found") and report["input"]:
                workspace.add_finding(
                    kind="satisfying_input",
                    summary=f"Satisfying input: {report['input']}",
                    source="symbolic",
                    confidence=1.0,
                )

        return report
