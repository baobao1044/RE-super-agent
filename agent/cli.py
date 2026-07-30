"""re-agent command-line entry point.

Usage:
  re-agent <binary> "<task>"            # one-shot analysis
  re-agent <binary> "<task>" --trace    # one-shot + print the workflow trace
  re-agent <binary> "<task>" --json     # one-shot, emit the report as JSON
  re-agent                              # interactive REPL (commands: run, trace, help, quit)

`main` builds a Supervisor from config (LLM provider + real specialists) and prints a
formatted report. `build_supervisor` is a seam: tests monkeypatch it to inject a fake
supervisor so no cloud LLM / Docker is needed.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

log = logging.getLogger(__name__)


# --------------------------------------------------------------------------- args
def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="re-agent",
        description="Super agent for professional reverse engineering.",
    )
    p.add_argument("binary", nargs="?", help="path to the target binary")
    p.add_argument("task", nargs="?", default="", help="the RE task to perform")
    p.add_argument("--trace", action="store_true",
                   help="print the workflow trace (DAG history + adaptation reasons)")
    p.add_argument("--json", action="store_true", help="emit the report as JSON")
    p.add_argument("--config", default=None, help="path to config.yaml")
    p.add_argument("--session-dir", default=None, help="directory for session/checkpoint state")
    return p.parse_args(argv)


# ----------------------------------------------------------------------- formatting
def format_report(report: dict) -> str:
    """Render the Supervisor report as human-readable text."""
    b = report.get("binary", {})
    lines = [
        "=" * 72,
        f"RE-super-agent report — task: {report.get('task', '')}",
        "=" * 72,
        f"Binary : {b.get('path', '?')}",
        f"Format : {b.get('format')} / {b.get('arch')} ({b.get('bits')}-bit)",
        f"Risk   : {report.get('risk_level', '?')}",
        "-" * 72,
        report.get("summary", ""),
        "-" * 72,
        "Workflow:",
    ]
    wf = report.get("workflow", {})
    for n in wf.get("nodes", []):
        lines.append(f"  [{n.get('status'):7}] {n.get('id')}: {n.get('sub_task')} "
                     f"({n.get('specialist')})")
    findings = report.get("findings", [])
    lines.append("-" * 72)
    lines.append(f"Findings ({len(findings)}):")
    for f in findings:
        lines.append(f"  #{f.get('id')} [{f.get('kind')}] {f.get('summary')} "
                     f"(source: {f.get('source')})")
    if report.get("vm_spec"):
        lines.append("-" * 72)
        lines.append(f"VM spec: {len(report['vm_spec'].get('opcodes', {}))} lifted opcodes "
                     f"@ {report['vm_spec'].get('dispatch_addr')}")
    return "\n".join(lines)


def format_trace(trace: list[dict]) -> str:
    """Render the workflow trace (DAG history + adaptation reasons)."""
    lines = ["=" * 72, "Workflow trace (DAG history + adaptation reasons)", "=" * 72]
    if not trace:
        lines.append("(no steps recorded)")
        return "\n".join(lines)
    for s in trace:
        action = s.get("action", "?")
        if action == "execute_node":
            lines.append(f"  [{s.get('status', '?'):7}] {s.get('node')}: "
                         f"{s.get('reason')} ({s.get('specialist')})")
        elif action == "skip_node":
            lines.append(f"  [skip   ] {s.get('node')}: precondition not met "
                         f"({s.get('specialist')})")
        elif action == "adapt":
            lines.append(f"  [adapt  ] {s.get('node')}: anomaly={s.get('anomaly')} "
                         f"| {s.get('reason')} [patch={s.get('patch_action')}]")
        elif action == "adapt_failed":
            lines.append(f"  [adapt-x] {s.get('node')}: {s.get('reason')}")
        else:
            lines.append(f"  [{action}] {s.get('node', '')}: {s.get('reason', '')}")
    return "\n".join(lines)


# ----------------------------------------------------------------- supervisor build
def build_supervisor(*, binary_path: str, config_path: str | None = None,
                     session_dir: str | None = None):
    """Construct the live Supervisor: LLM provider + real specialists wired to the MCP
    tool registries. `binary_path` is bound into each registry so tools act on the right
    target. Lazily imported so tests don't require config / cloud credentials.
    """
    from tools.config import load as load_config
    from agent.llm.provider import LiteLLMProvider
    from agent.core.supervisor import Supervisor
    from agent.specialists.malware import MalwareSpecialist
    from agent.specialists.static import StaticSpecialist
    from agent.specialists.dynamic import DynamicSpecialist
    from agent.specialists.symbolic import SymbolicSpecialist
    from agent.specialists.deobfuscation import DeobfuscationSpecialist

    cfg = load_config(config_path)
    llm_cfg = cfg.get("llm", {}) or {}
    wf_cfg = cfg.get("workflow", {}) or {}
    provider = LiteLLMProvider(
        model=llm_cfg.get("model", "gpt-4o-mini"),
        api_key=llm_cfg.get("api_key"),
        api_base=llm_cfg.get("api_base") or None,
        temperature=llm_cfg.get("temperature", 0.2),
        max_tokens=llm_cfg.get("max_tokens", 4096),
        timeout=llm_cfg.get("timeout", 120),
    )
    # Wire each specialist to its MCP server's tool registry (pure-logic backends degrade
    # gracefully when heavy engines are absent). binary_path is bound into the closures.
    specialists = {
        "malware": MalwareSpecialist(provider=provider,
                                     tools_registry=_malware_registry(binary_path)),
        "static": StaticSpecialist(provider=provider,
                                    tools_registry=_static_registry(binary_path)),
        "dynamic": DynamicSpecialist(provider=provider,
                                     tools_registry=_dynamic_registry(binary_path)),
        "symbolic": SymbolicSpecialist(provider=provider,
                                       tools_registry=_symbolic_registry(binary_path)),
        "deobfuscation": DeobfuscationSpecialist(provider=provider,
                                                  tools_registry=_deobf_registry(binary_path)),
    }
    return Supervisor(provider=provider, sandbox=_sandbox(),
                      specialists=specialists, playbooks_dir=cfg.get("playbooks_dir"),
                      codegen_dir=wf_cfg.get("codegen_dir", ".codegen"))


def _sandbox():
    from tools import sandbox
    return sandbox if sandbox.is_available() else None


def _malware_registry(binary_path: str):
    from mcp_servers.malware import server
    return {"risk_scan": lambda a: server.tool_risk_scan(binary_path),
            "extract_strings": lambda a: server.tool_extract_strings(binary_path,
                                                                      a.get("min_len", 4))}


def _static_registry(binary_path: str):
    from mcp_servers.static import server
    return {
        "list_functions": lambda a: server.tool_list_functions(binary_path),
        "decompile_function": lambda a: server.tool_decompile_function(binary_path,
                                                                       a.get("addr", 0)),
        "disassemble": lambda a: server.tool_disassemble(binary_path,
                                                          addr=a.get("addr", 0),
                                                          count=a.get("count", 20)),
        "xrefs_to": lambda a: server.tool_xrefs_to(binary_path, a.get("addr", 0)),
        "strings": lambda a: server.tool_strings(binary_path),
        "search_pattern": lambda a: server.tool_search_pattern(binary_path,
                                                                a.get("pattern", "")),
        "resolve_symbol": lambda a: server.tool_resolve_symbol(binary_path,
                                                                a.get("name", "")),
    }


def _dynamic_registry(binary_path: str):
    from mcp_servers.dynamic import server
    return {
        "spawn": lambda a: server.tool_spawn(binary_path),
        "run_restricted": lambda a: server.tool_run_restricted(
            binary_path, a.get("args", []),
            timeout=a.get("timeout", 20),
            risk_level=a.get("risk_level"),
            allow_host_fallback=bool(a.get("allow_host_fallback", False)),
        ),
        "attach": lambda a: server.tool_attach(a.get("pid", 0)),
        "detect_anti_analysis": lambda a: server.tool_detect_anti_analysis(binary_path),
        "recommend_handling": lambda a: server.tool_recommend_handling(a.get("anti_hints", [])),
        "get_regs": lambda a: server.tool_get_regs(),
    }


def _symbolic_registry(binary_path: str):
    from mcp_servers.symbolic import server
    return {
        "load_project": lambda a: server.tool_load_project(binary_path),
        "explore_to": lambda a: server.tool_explore_to(binary_path, a.get("addr", 0)),
        "find_input_satisfying": lambda a: server.tool_find_input_satisfying(a.get("predicate_str", "lambda x: True"),
                                                                              a.get("input_length", 1),
                                                                              a.get("alphabet_start", 0),
                                                                              a.get("alphabet_end", 256)),
        "extract_flag": lambda a: server.tool_extract_flag(a.get("flag_predicate_str", "lambda x: True"),
                                                           a.get("expected_len", 3),
                                                           a.get("alphabet_start", 65),
                                                           a.get("alphabet_end", 91)),
    }


def _deobf_registry(binary_path: str):
    from mcp_servers.deobfuscation import server
    return {
        "load_target": lambda a: server.tool_load_target(binary_path),
        "trace_execution": lambda a: server.tool_trace_execution(binary_path,
                                                                  max_steps=a.get("max_steps", 100)),
        "lift_vm_handler": lambda a: server.tool_lift_vm_handler(a.get("dispatch_addr", 0x402000),
                                                                  a.get("opcode", 0),
                                                                  a.get("name", ""),
                                                                  a.get("effects", ""),
                                                                  a.get("handler_addr")),
        "build_vm_spec": lambda a: server.tool_build_vm_spec(a.get("dispatch_addr", 0x402000),
                                                             a.get("handlers", [])),
        "disassemble_vm_bytecode": lambda a: server.tool_disassemble_vm_bytecode(a.get("spec", {}),
                                                                                  a.get("bytecode", b"")),
        "reconstruct_native": lambda a: server.tool_reconstruct_native(a.get("trace", []),
                                                                       dedup=a.get("dedup", False)),
        "hybrid_solve": lambda a: server.tool_hybrid_solve(a.get("trace", []),
                                                           a.get("predicate_str", "lambda x: False"),
                                                           a.get("input_length", 1),
                                                           a.get("alphabet_start", 0),
                                                           a.get("alphabet_end", 256)),
        "recover_python_source": lambda a: server.tool_recover_python_source(binary_path,
                                                                              max_disasm_lines=a.get("max_disasm_lines", 40)),
        "decompile_python_source": lambda a: server.tool_decompile_python_source(binary_path,
                                                                                  decompiler=a.get("decompiler", "pylingual"),
                                                                                  timeout=a.get("timeout", 120)),
    }


# --------------------------------------------------------------------------- main
def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    if args.binary is None:
        return _repl(args)

    if not Path(args.binary).exists():
        print(f"error: binary not found: {args.binary}", file=sys.stderr)
        return 2

    sup = build_supervisor(binary_path=args.binary, config_path=args.config,
                           session_dir=args.session_dir)
    report = sup.run(binary_path=args.binary, task=args.task)

    if args.json:
        print(json.dumps(report, indent=2, default=str))
        return 0

    print(format_report(report))
    if args.trace:
        print()
        print(format_trace(report.get("workflow_trace", [])))
    return 0


def _repl(args) -> int:
    """Interactive read-eval-print loop."""
    print("re-agent REPL. Commands: run <binary> <task>, trace, help, quit")
    sup = None
    last_report: dict | None = None
    while True:
        try:
            line = input("re-agent> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if not line:
            continue
        parts = line.split(maxsplit=1)
        cmd = parts[0].lower()
        rest = parts[1] if len(parts) > 1 else ""
        if cmd in ("quit", "exit"):
            return 0
        if cmd == "help":
            print("run <binary> <task>   analyze a binary\n"
                  "trace                  print the last workflow trace\n"
                  "quit                   exit")
            continue
        if cmd == "run":
            run_args = rest.split(maxsplit=1)
            if len(run_args) < 2:
                print("usage: run <binary> <task>", file=sys.stderr)
                continue
            binary, task = run_args[0], run_args[1]
            if not Path(binary).exists():
                print(f"error: binary not found: {binary}", file=sys.stderr)
                continue
            # Build (or rebuild) the supervisor bound to this binary.
            sup = build_supervisor(binary_path=binary, config_path=args.config,
                                   session_dir=args.session_dir)
            last_report = sup.run(binary_path=binary, task=task)
            print(format_report(last_report))
            continue
        if cmd == "trace":
            if last_report is None:
                print("no analysis yet — run <binary> <task> first")
                continue
            print(format_trace(last_report.get("workflow_trace", [])))
            continue
        print(f"unknown command: {cmd} (try: help)", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
