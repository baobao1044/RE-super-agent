# RE-super-agent

A **super agent for professional Reverse Engineering**. It combines:

- A **tool layer** of 5 domain **MCP servers** (static, dynamic, symbolic, deobfuscation, malware/CTF) wrapping real RE engines — Ghidra, radare2/rizin, angr, Frida, gdb/WinDbg, Qiling, capa, YARA, binwalk.
- A **multi-specialist orchestration** core (Python): a Supervisor that decomposes an RE goal and routes sub-tasks to 5 Specialists (static / dynamic / symbolic / deobfuscation / malware), each with its own ReAct loop and MCP client.
- A **dynamic workflow engine**: the agent *synthesizes a structured DAG* for each binary, executes it, and **self-adapts** (insert / backtrack / switch specialist) when tools return unexpected results. Effective workflows are saved as reusable **playbooks**.
- A **safety & isolation layer**: every dynamic execution and AI-generated code runs inside a lightweight **Docker sandbox**. A pre-flight **risk scan** classifies binaries (LOW / MEDIUM / HIGH) and selects the environment — Docker execution, Qiling emulation-in-Docker, human-in-the-loop confirmation, or static-only refusal.

Targets **Windows PE** and **Linux ELF** (x86 / x64).

## Status

Scaffolding stage. See the build plan in `docs/` (added as stages land). Currently implements:
- Binary metadata detection (PE/ELF format + arch + basic risk heuristics) — `tools/binary.py`
- Sandbox shell + risk gate — `tools/sandbox.py`, `agent/core/safety.py`

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

## Layout

```
mcp_servers/   5 MCP servers (static, dynamic, symbolic, deobfuscation, malware)
agent/         supervisor + specialists + workflow engine + safety + state + llm + cli
tools/         binary parsing, config, logging, sandbox spawn
docker/        sandbox image entrypoint, seccomp profile, code-gen runner
samples/       tiny test binaries (crackme, flag-checker, packed, suspicious)
tests/         unit + integration
```

## License

MIT.
