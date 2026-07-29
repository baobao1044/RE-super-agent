"""Static analysis specialist — runs a ReAct loop over the static MCP tools and writes
discovered functions / strings / instructions / pattern matches into the workspace.

The specialist captures structured results from the high-value tools (strings,
disassemble, list_functions, search_pattern) and records them both in its returned
report and as workspace findings, so downstream specialists (symbolic/dynamic) can
consume them (e.g. a string address -> a hook target).
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Callable

from agent.core.react_loop import react_loop
from agent.state.workspace import Workspace

log = logging.getLogger(__name__)

DEFAULT_SYSTEM_PROMPT = """You are the static analysis specialist of a reverse-engineering
super agent. You analyze a binary WITHOUT running it (pure static).

Available tools (all take the binary path implicitly):
- load_binary(path): detect format/arch/metadata.
- list_functions(path): list discovered functions (Ghidra or r2; may be unavailable).
- decompile_function(path, addr): decompile at an address (Ghidra only; may be unavailable).
- disassemble(path, addr, count, arch, bits, file_offset): disassemble raw bytes (capstone, always available).
- xrefs_to(path, addr): cross-references to an address.
- strings(path, min_len): extract ASCII strings + entropy.
- resolve_symbol(path, name): resolve a symbol to an address (r2).
- search_pattern(path, pattern): find a hex byte pattern.

Rules:
1. Start with load_binary to know the format/arch.
2. Use strings to surface interesting markers (passwords, flags, error messages, suspicious APIs).
3. Use disassemble to read the entry point or any address of interest.
4. Report what you found (functions, strings, instructions, matches) concisely.
5. If an engine is unavailable, say so and rely on the capstone disassembly fallback.
Never claim a function's behavior without evidence from disassembly or decompilation.
"""


class _CapturingRegistry:
    """Wraps a tool registry; records structured results from high-value tools."""

    def __init__(self, inner: dict[str, Callable]):
        self._inner = inner
        self.captured: dict[str, dict] = {}

    def execute(self, name: str, arguments: dict):
        result = self._inner[name](arguments) if name in self._inner else {"error": f"unknown tool {name}"}
        if name in ("strings", "disassemble", "list_functions", "search_pattern"):
            self.captured[name] = result
        return result


class StaticSpecialist:
    def __init__(self, provider, tools_registry, system_prompt: str = DEFAULT_SYSTEM_PROMPT):
        self.provider = provider
        self.tools_registry = tools_registry
        self.system_prompt = system_prompt

    def run(self, *, task: str, binary_path: str | Path, workspace: Workspace) -> dict:
        path = str(binary_path)
        cap = _CapturingRegistry(self.tools_registry)

        tools = [
            {"type": "function", "function": {"name": "load_binary",
              "description": "Detect binary format/arch/metadata.",
              "parameters": {"type": "object", "properties": {}}}},
            {"type": "function", "function": {"name": "list_functions",
              "description": "List discovered functions.",
              "parameters": {"type": "object", "properties": {}}}},
            {"type": "function", "function": {"name": "disassemble",
              "description": "Disassemble bytes at a virtual address.",
              "parameters": {"type": "object", "properties": {
                  "addr": {"type": "integer"}, "count": {"type": "integer"}}}}},
            {"type": "function", "function": {"name": "strings",
              "description": "Extract ASCII strings + entropy.",
              "parameters": {"type": "object", "properties": {"min_len": {"type": "integer"}}}}},
            {"type": "function", "function": {"name": "search_pattern",
              "description": "Search for a hex byte pattern.",
              "parameters": {"type": "object", "properties": {"pattern": {"type": "string"}}}}},
        ]

        result = react_loop(
            provider=self.provider,
            registry=cap,
            messages=[{"role": "user", "content": f"{task}\nBinary path: {path}"}],
            tools=tools,
            system=self.system_prompt,
        )

        # Assemble captured structured data into the report + workspace findings.
        report: dict = {
            "narrative": result.final_text,
            "strings": [],
            "instructions": [],
            "functions": [],
            "matches": [],
            "steps": [{"tool": s.tool_name, "error": s.tool_error} for s in result.steps],
            "truncated": result.truncated,
        }

        if "strings" in cap.captured:
            strs = cap.captured["strings"].get("strings", [])
            report["strings"] = strs
            if strs:
                workspace.add_finding(
                    kind="strings",
                    summary=f"Found {len(strs)} strings incl. {strs[:3]}",
                    source="static",
                )

        if "disassemble" in cap.captured:
            insns = cap.captured["disassemble"].get("instructions", [])
            report["instructions"] = insns
            if insns:
                workspace.add_finding(
                    kind="disassembly",
                    summary=f"Disassembled {len(insns)} instructions; first: "
                            f"{insns[0]['mnemonic']} {insns[0]['op_str']} @ {hex(insns[0]['addr'])}",
                    source="static",
                )

        if "list_functions" in cap.captured:
            funcs = cap.captured["list_functions"].get("functions", [])
            report["functions"] = funcs
            for fn in funcs:
                addr = fn.get("addr")
                if isinstance(addr, int):
                    workspace.add_function(addr=addr, name=fn.get("name", ""),
                                          source="static")

        if "search_pattern" in cap.captured:
            matches = cap.captured["search_pattern"].get("matches", [])
            report["matches"] = matches
            if matches:
                workspace.add_finding(
                    kind="pattern_match",
                    summary=f"Pattern matched at {len(matches)} offsets: "
                            f"{[m.get('offset') for m in matches][:5]}",
                    source="static",
                )

        return report
