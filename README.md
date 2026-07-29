# RE-super-agent

A **super agent for professional Reverse Engineering**. It combines:

- A **tool layer** of 5 domain **MCP servers** (static, dynamic, symbolic, deobfuscation, malware/CTF) wrapping real RE engines — Ghidra, radare2/rizin, angr, Frida, gdb/WinDbg, Qiling, capa, YARA, binwalk.
- A **multi-specialist orchestration** core (Python): a Supervisor that decomposes an RE goal and routes sub-tasks to 5 Specialists (static / dynamic / symbolic / deobfuscation / malware), each with its own ReAct loop and MCP client.
- A **dynamic workflow engine**: the agent *synthesizes a structured DAG* for each binary, executes it, and **self-adapts** (insert / backtrack / switch specialist) when tools return unexpected results. Effective workflows are saved as reusable **playbooks**.
- A **safety & isolation layer**: every dynamic execution and AI-generated code runs inside a lightweight **Docker sandbox**. A pre-flight **risk scan** classifies binaries (LOW / MEDIUM / HIGH) and selects the environment — Docker execution, Qiling emulation-in-Docker, human-in-the-loop confirmation, or static-only refusal.

Targets **Windows PE** and **Linux ELF** (x86 / x64).

## Status

**Implementation complete (Stages 1–10).** The full hybrid stack is implemented and tested
(256 tests green, TDD throughout). Backends degrade gracefully when heavy engines are
absent (pure-Python fallbacks for disassembly, constraint solving, string extraction, VM
lifting), so the core boots and analyzes binaries on a minimal install.

Implemented:
- **Binary metadata + risk heuristics** — `tools/binary.py` (PE/ELF parse, arch, risk hints)
- **5 MCP servers** with real backends + graceful degrade:
  - `mcp_servers/static/` — Ghidra (pyghidra) + radare2/rizin, capstone fallback
  - `mcp_servers/dynamic/` — Frida + gdb + WinDbg, anti-analysis cluster
  - `mcp_servers/symbolic/` — angr + pure-Python brute-force constraint solver
  - `mcp_servers/deobfuscation/` — Qiling trace, VM handler lifting, trace-driven devirtualization
  - `mcp_servers/malware/` — capa + YARA + binwalk + risk policy (LOW/MEDIUM/HIGH)
- **5 Specialists** — `agent/specialists/` — each a ReAct loop over its MCP tools
- **Dynamic workflow engine** — `agent/core/workflow.py`:
  - `synthesize` — LLM designs a declarative DAG (schema-validated, re-prompted; playbook fallback)
  - `execute` — topological run, branch conditions (success/fail/always), resume skips done nodes
  - `adapt` — self-modification on anomalies (VM detected / symbolic explode / node failure): insert_after / replace_node / switch_specialist / backtrack
  - `checkpoint_save` / `checkpoint_load` — durable resume after interruption
  - code-gen node — LLM-generated Python run inside the Docker sandbox (never host), result → workspace
- **Playbook library** — `agent/core/playbooks/` — 4 bundled templates (crackme / packed_vm / malware / ctf); `save_playbook` / `load_playbook` reuse successful workflows
- **Supervisor + planner** — `agent/core/supervisor.py`, `agent/core/planner.py`: analyze → risk scan → synth → adaptive execute → report
- **CLI** — `agent/cli.py`: one-shot, `--trace` (workflow trace view), `--json`, and an interactive REPL (`run`, `trace`, `help`, `quit`)
- **Safety** — `tools/sandbox.py` (hardened Docker: no network, dropped caps, read-only, tmpfs noexec) + `agent/core/safety.py` (risk gate; HIGH → static-only; never host exec when Docker missing)

## Quick start

```bash
# 1. Install host-side Python deps (core subset boots without heavy engines)
python -m pip install -e ".[dev]"
# Optional: install full RE engine stack
python -m pip install -e ".[full]"

# 2. Install system RE tools (Ghidra, radare2, Frida, debuggers, ...)
#    Linux / macOS:
./install.sh core       # minimal
./install.sh full       # everything
#    Windows (PowerShell):
./install.ps1 core
./install.ps1 full

# 3. Build the sandbox image (required for dynamic / code-gen execution)
docker build --target core -t re-agent:core  -f Dockerfile .
docker build --target full -t re-agent:full  -f Dockerfile .

# 4. Configure
cp config/config.example.yaml config/config.yaml
# edit config/config.yaml: set LLM provider + API key + binary paths

# 5. Run
re-agent ./samples/crackme.elf "find and bypass the password check"
```

## Safety model

The agent **never** executes an untrusted binary or LLM-generated code on the host. All execution goes through:

1. **Pre-flight risk scan** (capa/YARA + heuristics) → `LOW` / `MEDIUM` / `HIGH`.
2. **Environment selection**:
   - `LOW` → run inside the `re-agent:full` Docker sandbox (no network, dropped capabilities, resource-limited).
   - `MEDIUM` → Qiling emulation *inside* Docker first; real execution requires explicit human confirmation.
   - `HIGH` (kernel driver, wiper signature, known anti-VM escape) → **static-only**, dynamic/code-gen refused.

This is a research / CTF / authorized-malware-analysis tool. Only analyze binaries you are authorized to analyze.

## Dynamic workflow engine

The centerpiece the agent uses to work efficiently on hard targets. Instead of a fixed
script, the Supervisor + LLM **synthesize a declarative DAG** for each binary, then the
engine executes it and **self-adapts** when reality diverges from the plan.

A DAG node is `{sub-task, specialist, tool, branch condition}`; edges carry conditions
(`success` / `fail` / `always`) so the workflow can branch (e.g. a failed risk scan routes
straight to a sandbox-confirmation node instead of static analysis).

**Adaptive self-modification** triggers on anomalies detected from node outputs:
- `vm_detected` (a packed/VM obfuscator) → `insert_after` a deobfuscation node to lift VM
  handlers and devirtualize before the symbolic solver runs (avoids path explosion).
- `symbolic_explode` (too many states explored) → `insert_after` trace-narrowing, then `backtrack`.
- `node_failed` (engine missing, function not found) → `switch_specialist` to an alternate
  backend, or `backtrack` for a transient failure.

Each adaptation records its reason in the **workflow trace** so the user can see *why* the
agent changed direction. The trace is printed with `re-agent <bin> <task> --trace`.

**Playbooks**: a successful (or analyst-curated) workflow is saved as a parametrized template
keyed by binary type. Four are bundled in `agent/core/playbooks/` (crackme, packed_vm,
malware, ctf) and used as the synthesis fallback when the LLM cannot design a valid DAG.

**Checkpoint/resume**: `WorkflowEngine.checkpoint_save` persists the full DAG + workspace;
`checkpoint_load` resets interrupted (mid-run) nodes to `pending` and skips `done` nodes,
so a long analysis resumes after an interruption.

## Examples

```bash
# Crackme: locate + bypass a license check (risk-scan → static → symbolic → dynamic confirm)
re-agent ./crackme.exe "bypass the license check"

# CTF flag-checker: solve the constraint to recover the flag
re-agent ./checker.elf "extract the flag"
re-agent ./checker.elf "extract the flag" --json     # machine-readable report

# Packed / VM-obfuscated: engine detects the VM, inserts a devirtualization node,
# lifts handlers, disassembles bytecode, then solves the recovered check
re-agent ./packed.exe "devirtualize and bypass"
re-agent ./packed.exe "devirtualize and bypass" --trace   # show the adaptive DAG history

# Suspicious sample: HIGH risk → static-only, dynamic/code-gen refused
re-agent ./sample.exe "analyze its behavior"

# Interactive REPL
re-agent
re-agent> run ./crackme.exe "bypass the license check"
re-agent> trace
re-agent> quit
```

## Layout

```
mcp_servers/   5 MCP servers (static, dynamic, symbolic, deobfuscation, malware)
agent/
  core/        supervisor, planner, react_loop, safety, workflow + playbooks/
  specialists/ 5 specialists (static, dynamic, symbolic, deobfuscation, malware)
  state/       workspace (shared RE state across specialists)
  llm/         LiteLLM provider (cloud, agnostic)
  cli.py       re-agent entry point (one-shot + REPL + --trace/--json)
  mcp_client.py
tools/         binary parsing, config, logging, sandbox spawn
docker/        sandbox image entrypoint, seccomp profile, code-gen runner
config/        config.example.yaml
tests/         unit + integration (256 tests)
```

## License

MIT.
