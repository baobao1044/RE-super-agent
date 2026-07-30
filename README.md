<div align="center">

# 🔬 RE-super-agent

**A super agent for professional Reverse Engineering**

A hybrid architecture combining 5 domain MCP servers, a Python multi-specialist
orchestration core, a dynamic self-adapting workflow engine, and a safety/isolation layer.

Targets **Windows PE** & **Linux ELF** (x86 / x64) · **Python-protector-obfuscated** files

[![Status](https://img.shields.io/badge/status-stages%201--10%20complete-brightgreen)](#status)
[![Tests](https://img.shields.io/badge/tests-298%20green-success)](#testing)
[![TDD](https://img.shields.io/badge/method-TDD%20RED%E2%86%92GREEN%E2%86%92REFACTOR-blue)](#testing)
[![Python](https://img.shields.io/badge/python-3.11%2B-yellow)](https://www.python.org)
[![License](https://img.shields.io/badge/license-MIT-lightgrey)](#license)
[![LLM](https://img.shields.io/badge/LLM-provider--agnostic%20(LiteLLM)-orange)](#configuration)

</div>

> ⚠️ **For research, CTF, and authorized malware analysis only.** Only analyze binaries
> you are authorized to analyze. Never execute untrusted code on the host — the agent
> routes all dynamic execution through an isolated sandbox.

---

## Table of contents

1. [Architecture — Mindmap](#architecture--mindmap)
2. [Key capabilities](#key-capabilities)
3. [Quick start](#quick-start)
4. [Usage](#usage)
5. [Python-protector deobfuscation](#python-protector-deobfuscation)
6. [Safety model](#safety-model)
7. [Dynamic workflow engine](#dynamic-workflow-engine)
8. [MCP tool surface](#mcp-tool-surface)
9. [Project layout](#project-layout)
10. [Configuration](#configuration)
11. [Testing](#testing)
12. [Status](#status)
13. [License](#license)

---

## Architecture — Mindmap

```
                                    RE-super-agent
                                         │
            ┌────────────────────────────┼─────────────────────────────┐
            │                            │                             │
      ┌─────▼─────┐              ┌───────▼────────┐            ┌───────▼──────┐
      │   CLI     │              │  Orchestration │            │   Safety     │
      │ re-agent  │──→ Supervisor │  (Python core) │            │  & Isolation │
      └─────┬─────┘              └───────┬────────┘            └───────┬──────┘
            │                            │                             │
            │                     ┌──────┼──────┐                      │
            │                     │      │      │                      │
            │              Workflow   ReAct   Workspace          Risk Scan
            │              Engine    Loop     (shared state)     → LOW/MED/HIGH
            │            (DAG synth,   (per                          │
            │             adapt,       specialist)          ┌───────┴───────┐
            │             checkpoint)                       │               │
            │                    │                   Docker Sandbox   Static-only
            │                    │                   (no-network,    (HIGH risk
            │            ┌───────┴───────┐            cap-drop,        refusal)
            │            │   Playbooks   │            read-only)
            │            │ (crackme/CTF/ │
            │            │  malware/VM)  │
            │            └───────────────┘
            │
   ┌────────┴──────────────────────────────────────────────────────────────┐
   │                        5 Domain Specialists                            │
   │                                                                        │
   │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────────┐  ┌─────────┐│
   │  │  Static   │  │ Dynamic  │  │ Symbolic │  │Deobfuscate │  │ Malware ││
   │  └─────┬────┘  └─────┬────┘  └─────┬────┘  └─────┬──────┘  └────┬────┘│
   │        │             │             │             │               │     │
   │  ┌─────▼────┐  ┌─────▼────┐  ┌─────▼────┐  ┌─────▼──────┐  ┌────▼────┐│
   │  │MCP Server│  │MCP Server│  │MCP Server│  │MCP Server  │  │MCP Server││
   │  │Ghidra+r2 │  │Frida+gdb │  │  angr    │  │Qiling+VM   │  │capa+YARA ││
   │  │+capstone │  │+WinDbg   │  │  +brute  │  │+LLM lifter │  │+binwalk  ││
   │  │  (8 tools)│  │ (16 tools)│  │ (5 tools)│  │  (9 tools) │  │ (6 tools)││
   │  └──────────┘  └──────────┘  └──────────┘  └────────────┘  └─────────┘│
   └────────────────────────────────────────────────────────────────────────┘
```

---

## Key capabilities

| Capability | What it does |
|:---|:---|
| 🛠️ **5 MCP servers** | 44 tools total, wrapping Ghidra, radare2/rizin, angr, Frida, gdb, WinDbg, Qiling, capa, YARA, binwalk. Graceful degrade when engines missing (pure-Python fallbacks). |
| 🧠 **5 Specialists** | Each runs a ReAct loop (reason→act→observe) over its MCP tools, with domain-specific system prompts. |
| 🔄 **Dynamic workflow engine** | LLM synthesizes a declarative DAG per binary; engine self-adapts on anomalies (VM detected → insert deobf node; symbolic explode → trace-narrow + backtrack; node failed → switch specialist). Checkpoint/resume for long analyses. |
| 📚 **Playbook library** | 4 bundled templates (crackme / packed_vm / malware / ctf); successful workflows saved & reused. |
| 🛡️ **Safety layer** | Pre-flight risk scan (LOW/MEDIUM/HIGH) → Docker sandbox / Qiling-in-Docker / human confirm / static-only refusal. Never executes untrusted code on host. |
| 🐍 **Python deobfuscation** | Safe static RE of enphysic.pro/Ngocuyencoder-protected `.py` files — deserialize custom marshal → structural lifter → **agentic LLM decompiler** recovers real Python source (if/for/try-except) via LLM API. Never executes protected code. |

---

## Quick start

```bash
# 1. Install Python deps (core subset boots without heavy engines)
python -m pip install -e ".[dev]"

# Optional: full RE engine stack
python -m pip install -e ".[full]"

# 2. Install system RE tools + build Docker sandbox image
#    Linux / macOS:
./install.sh core      # minimal (static + malware)
./install.sh full      # everything (angr, qiling, frida, ghidra, ...)
#    Windows (PowerShell):
./install.ps1 core
./install.ps1 full

# 3. Build sandbox images (required for dynamic / code-gen execution)
docker build --target core -t re-agent:core  -f Dockerfile .
docker build --target full -t re-agent:full -f Dockerfile .

# 4. Configure LLM
cp config/config.example.yaml config/config.yaml
#    Edit config.yaml — set your LLM provider + API key:
#      llm:
#        provider: openai
#        model: gpt-4o-mini          # or openai/zai-org/GLM-5.2 for W&B Inference
#        api_key: sk-your-openai-api-key  # or api_key_env: OPENAI_API_KEY
#        api_base: ""                # custom endpoint, or https://api.inference.wandb.ai/v1

# 5. Run
re-agent ./samples/crackme.elf "find and bypass the password check"
```

### Using W&B Inference (GLM-5.2)

```yaml
# config/config.yaml
llm:
  provider: openai
  model: openai/zai-org/GLM-5.2
  api_key: wandb_v1_your-key-here
  api_base: https://api.inference.wandb.ai/v1
  temperature: 0.2
  max_tokens: 4096
  timeout: 120
```

> **Never commit `config/config.yaml`** — it contains your API key. The file is
> gitignored. Use `config/config.example.yaml` as the template.

---

## Usage

```bash
# One-shot analysis
re-agent <binary> "<task>"

# One-shot + print the workflow trace (DAG history + adaptation reasons)
re-agent <binary> "<task>" --trace

# One-shot, emit machine-readable JSON report
re-agent <binary> "<task>" --json

# Custom config / session dir
re-agent <binary> "<task>" --config my-config.yaml --session-dir ./sessions

# Interactive REPL
re-agent
re-agent> run ./crackme.exe "bypass the license check"
re-agent> trace
re-agent> quit
```

### Examples

```bash
# Crackme: locate + bypass a license check
re-agent ./crackme.exe "bypass the license check"

# CTF flag-checker: solve the constraint to recover the flag
re-agent ./checker.elf "extract the flag" --json

# Packed / VM-obfuscated: engine auto-detects VM, inserts devirtualization
re-agent ./packed.exe "devirtualize and bypass" --trace

# Suspicious sample: HIGH risk → static-only, dynamic refused
re-agent ./sample.exe "analyze its behavior"

# Protected Python file: deobfuscate full source
re-agent ./protected_app.py "deobfuscate the full source"
```

---

## Python-protector deobfuscation

RE-super-agent includes a **safe static deobfuscation pipeline** for Python files protected
by `enphysic.pro / Ngocuyencoder`. The protection scheme is: `base64 → LZMA → custom marshal
serializer → 4 version blobs → CJK identifier obfuscation`.

The pipeline **never executes** the protected code — it only deserializes + analyzes:

```
Protected .py file
       │
       ▼
  extract_payload_blob()      ← parse _B['p'] (AST, no exec)
       │
       ▼
  lzma.decompress(b64decode)  ← decompress payload
       │
       ▼
  custom deserializer          ← reconstruct code object (no exec)
  (tags c/t/r/l/P/s/b/i/g/...)
       │
       ├──→ recover_python_source()  ← structural summary (names, consts, scopes, disasm)
       │
       ├──→ decompile_python_source() ← custom structural lifter
       │    (exact def/class signatures + annotated bytecode)
       │
       └──→ decompile_python_source_llm()  ← agentic LLM decompiler
            (translates bytecode annotations → real if/for/try-except source via LLM API)
```

The **agentic LLM decompiler** (`tools/llm_lifter.py`) uses the configured LLM provider
(e.g., GLM-5.2) to translate bytecode annotations into real Python source with actual
control flow — `if`/`for`/`while`/`try-except`/comprehension — instead of raw bytecode
comments. This reuses the agent's LLM API without pulling a 2GB+ ML decompiler dependency.

---

## Safety model

The agent **never** executes an untrusted binary or LLM-generated code on the host.

```
            Binary
               │
        ┌──────▼──────┐
        │  Risk Scan  │  capa + YARA + heuristics
        └──────┬──────┘
               │
    ┌──────────┼──────────┐
    │          │          │
  LOW       MEDIUM      HIGH
    │          │          │
    ▼          ▼          ▼
 Docker     Qiling-in    Static-only
 sandbox    Docker +     (dynamic + code-gen
 (no-net,   human        refused)
 cap-drop,  confirm
 ro, tmpfs) for real exec
```

- **LOW** → run inside `re-agent:full` Docker sandbox (no network, dropped capabilities,
  read-only root, tmpfs `/scratch` with `noexec`).
- **MEDIUM** → Qiling emulation *inside* Docker first; real execution requires explicit
  human confirmation.
- **HIGH** (kernel driver, wiper signature, known anti-VM escape) → **static-only**,
  dynamic/code-gen refused.
- When Docker is unavailable: the agent degrades to **static-only** — never executes on host.

### Docker sandbox hardening

Every sandboxed run applies:
`--network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges
--memory=2g --cpus=2 --pids-limit=256 --tmpfs /scratch:rw,noexec,nosuid,nodev`

### Restricted subprocess (opt-in fallback)

When Docker is unavailable, an opt-in weak-isolation `run_restricted` tool provides
best-effort isolation: throwaway temp scratch dir (target copied, originals untouched),
scrubbed environment (only benign OS whitelist), DEVNULL stdin, hard timeout, bounded
stdout/stderr. Requires explicit `allow_host_fallback=True` — only for runnable targets
where the user accepted the risk.

---

## Dynamic workflow engine

The centerpiece for working efficiently on hard targets. Instead of a fixed script, the
Supervisor + LLM **synthesize a declarative DAG** per binary, then the engine executes it
and **self-adapts** when reality diverges from the plan.

```
  User task → Supervisor
       │
       ▼
  ┌──────────┐    ┌──────────────┐    ┌──────────┐
  │  Synth   │───→│   Execute   │───→│  Observe  │
  │ (LLM DAG)│    │ (topological)│    │ (outputs) │
  └──────────┘    └──────┬───────┘    └─────┬────┘
       ▲                  │                  │
       │            ┌─────▼─────┐     ┌─────▼─────┐
       │            │  Checkpoint │     │  Anomaly?  │
       │            │  (resume)   │     └─────┬─────┘
       │            └────────────┘           │
       └────────────────────────── yes ───────┘
              adapt: insert_after / replace_node /
              switch_specialist / backtrack
```

A DAG node is `{sub-task, specialist, tool, branch condition}`; edges carry conditions
(`success` / `fail` / `always`).

**Adaptive self-modification** triggers on anomalies:
- `vm_detected` → `insert_after` a deobfuscation node (lift VM handlers before symbolic).
- `symbolic_explode` → `insert_after` trace-narrowing, then `backtrack`.
- `node_failed` → `switch_specialist` to an alternate backend, or `backtrack`.

Each adaptation records its reason in the **workflow trace** (`--trace` flag).

**Playbooks**: 4 bundled templates in `agent/core/playbooks/` (crackme, packed_vm,
malware, ctf). Successful workflows are saved & reused.

**Checkpoint/resume**: `checkpoint_save` persists the full DAG + workspace;
`checkpoint_load` resets interrupted nodes to `pending`, skips `done` nodes.

---

## MCP tool surface

### Static (8 tools)
`load_binary`, `list_functions`, `decompile_function(addr)`, `disassemble(addr, count)`,
`xrefs_to(addr)`, `strings`, `resolve_symbol(name)`, `search_pattern(hex)`.
Backends: Ghidra (pyghidra) + radare2/rizin, capstone fallback.

### Dynamic (16 tools)
`spawn`, `run_restricted`, `attach`, `list_processes`, `set_breakpoint`, `continue`,
`step`, `read_memory`, `write_memory`, `hook_function`, `get_regs`, plus anti-analysis:
`detect_anti_analysis`, `recommend_handling`, `patch_anti_debug`, `hide_debugger`,
`emulate_clean_environment`.
Backends: Frida + gdb + WinDbg.

### Symbolic (5 tools)
`load_project`, `explore_to(addr)`, `find_input_satisfying(constraint)`,
`extract_flag(predicate)`, `get_state_info`.
Backends: angr + pure-Python brute-force solver.

### Deobfuscation (9 tools)
`load_target`, `trace_execution`, `lift_vm_handler`, `build_vm_spec`,
`disassemble_vm_bytecode`, `reconstruct_native`, `hybrid_solve`, `recover_python_source`,
`decompile_python_source` + agentic `decompile_python_source_llm` (provider-injected).
Backends: Qiling + VM lifter + custom LLM decompiler.

### Malware/CTF (6 tools)
`risk_scan`, `scan_yara(rules)`, `capa_analysis`, `binwalk_extract`,
`extract_strings`, `recommend_environment`.
Backends: capa + YARA + binwalk + risk policy.

---

## Project layout

```
RE-super-agent/
├── README.md
├── pyproject.toml                 # re-agent entry point, core/optional deps
├── install.sh / install.ps1       # system tools + Docker (core|full tiers)
├── Dockerfile                     # sandbox image (core|full build targets)
├── docker/                        # sandbox entrypoint, seccomp, code-gen runner
├── config/
│   ├── config.example.yaml        # template (copy → config.yaml, never commit)
│   └── config.yaml                 # gitignored — your LLM key + settings
├── mcp_servers/                   # 5 domain MCP servers (44 tools total)
│   ├── static/      server.py, ghidra_backend.py, r2_backend.py
│   ├── dynamic/      server.py, frida_backend.py, gdb_backend.py, windbg_backend.py, anti_analysis.py
│   ├── symbolic/     server.py, angr_backend.py
│   ├── deobfuscation/ server.py, qiling_backend.py, vm_lifter.py, trace_reconstruct.py
│   └── malware/      server.py, capa_backend.py, yara_backend.py, binwalk_backend.py, risk_policy.py
├── agent/
│   ├── core/
│   │   ├── supervisor.py           # analyze → risk scan → synth → adaptive execute → report
│   │   ├── planner.py              # task decomposition
│   │   ├── react_loop.py           # reason→act→observe loop (with tool result truncation)
│   │   ├── safety.py               # risk gate (LOW/MEDIUM/HIGH → environment)
│   │   ├── workflow.py             # WorkflowEngine: synth/execute/adapt/checkpoint/playbook
│   │   └── playbooks/              # 4 bundled templates (crackme, packed_vm, malware, ctf)
│   ├── specialists/                # 5 specialists, each a ReAct loop + system prompt
│   │   ├── static.py, dynamic.py, symbolic.py, deobfuscation.py, malware.py
│   ├── state/
│   │   └── workspace.py            # shared RE state (findings, vm_spec, functions, ...)
│   ├── llm/
│   │   └── provider.py             # LiteLLM provider (cloud, agnostic, GLM reasoning_content support)
│   ├── mcp_client.py               # stdio MCP client
│   └── cli.py                      # re-agent entry point (one-shot + REPL + --trace/--json)
├── tools/
│   ├── binary.py                   # PE/ELF parse, arch detection, risk hints
│   ├── config.py                   # YAML config loader
│   ├── sandbox.py                  # Docker sandbox + restricted-subprocess fallback
│   ├── eps_deobf.py                # enphysic.pro/Ngocuyencoder safe deobfuscator
│   ├── decompile_lifter.py         # custom structural bytecode→source lifter
│   └── llm_lifter.py              # agentic LLM decompiler (bytecode annotations → real source)
└── tests/                          # 298 tests (unit + integration, TDD throughout)
```

---

## Configuration

```yaml
# config/config.yaml
llm:
  provider: openai                          # openai | claude | gemini (any LiteLLM model string)
  model: gpt-4o-mini                        # or openai/zai-org/GLM-5.2 for W&B Inference
  api_key: sk-your-openai-api-key            # or api_key_env: OPENAI_API_KEY
  api_base: ""                              # custom endpoint (W&B Inference, Azure, Ollama)
  temperature: 0.2
  max_tokens: 4096
  timeout: 120

specialists:                                 # per-specialist model overrides (optional)
  static:        { model: "" }
  dynamic:       { model: "" }
  symbolic:      { model: "" }
  deobfuscation: { model: "" }
  malware:       { model: "" }
  supervisor:    { model: "" }

mcp:                                         # MCP servers (stdio spawn)
  servers:
    static:        { command: "python", args: ["-m", "mcp_servers.static.server"] }
    dynamic:       { command: "python", args: ["-m", "mcp_servers.dynamic.server"] }
    symbolic:      { command: "python", args: ["-m", "mcp_servers.symbolic.server"] }
    deobfuscation: { command: "python", args: ["-m", "mcp_servers.deobfuscation.server"] }
    malware:       { command: "python", args: ["-m", "mcp_servers.malware.server"] }
  tool_timeout: 120

safety:
  require_confirmation: true                 # human confirm for MEDIUM-risk real execution
  refuse_high_risk: true                     # refuse HIGH-risk dynamic entirely
  sandbox_image_core: "re-agent:core"
  sandbox_image_full: "re-agent:full"
  docker_unavailable_fallback: static_only   # never execute on host if Docker missing

engines:                                     # auto-detected if not set (auto | true | false)
  ghidra:    { enabled: auto, install_path: "" }
  radare2:   { enabled: auto }
  angr:      { enabled: auto }
  frida:     { enabled: auto }
  qiling:    { enabled: auto }
  capstone:  { enabled: auto }
  capa:      { enabled: auto }
  yara:      { enabled: auto }
  binwalk:   { enabled: auto }

workflow:
  max_adaptations: 8                         # max self-adaptations per run
  persist_playbooks: true                    # save successful workflows
  codegen_dir: ".codegen"                    # generated code (sandboxed execution)
  symbolic_state_budget: 50000               # avoid path explosion

state:
  workspace_dir: "sessions"
  log_dir: "logs"
```

---

## Testing

```bash
# Full suite (298 tests)
python -m pytest

# With coverage
python -m pytest --cov=agent --cov=mcp_servers --cov=tools

# Specific area
python -m pytest tests/test_workflow.py tests/test_sandbox_subprocess.py tests/test_llm_lifter.py
```

All tests use TDD (RED → GREEN → REFACTOR). Heavy engines are mocked — tests pass without
Docker, Ghidra, angr, Frida, or any cloud LLM.

---

## Status

**Implementation complete (Stages 1–10).** 298 tests green, TDD throughout (RED → GREEN →
REFACTOR at every stage). Backends degrade gracefully when heavy engines are absent, so the
core boots and analyzes binaries on a minimal install.

| Stage | Focus | Status |
|:---:|:---|:---:|
| 1 | Binary parsing, PE/ELF detection, risk hints | ✅ |
| 2 | MCP servers (44 tools) + backends | ✅ |
| 3 | Specialists + ReAct loop | ✅ |
| 4 | Supervisor + planner + workspace | ✅ |
| 5 | Safety layer (risk gate, Docker, refusal) | ✅ |
| 6 | Dynamic workflow engine (DAG synth + adapt) | ✅ |
| 7 | Playbooks + checkpoint/resume | ✅ |
| 8 | Restricted-subprocess fallback (no-Docker isolation) | ✅ |
| 9 | Agentic LLM decompiler (bytecode → real source) | ✅ |
| 10 | Docs, README, GitHub polish | ✅ |

**Verified live:** the agent RE'd a `enphysic.pro/Ngocuyencoder`-protected Python file
end-to-end — recovered the protector identity, 7 nested scopes, bytecode disassembly, and
real Python source with control flow via the agentic LLM decompiler (GLM-5.2).

---

## License

MIT. See [`LICENSE`](LICENSE) for details.

---

<div align="center">

<sub>Built as a research platform for professional reverse engineering.<br>
🔐 Only analyze binaries you are authorized to analyze.</sub>

</div>
