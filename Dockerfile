# RE-super-agent sandbox image.
# Build a tier with --target:
#   docker build --target core -t re-agent:core  -f Dockerfile .
#   docker build --target full -t re-agent:full  -f Dockerfile .
#
# core: static (r2) + malware (risk/YARA/binwalk) + agent tools — no binary execution engines.
# full: core + angr + Qiling + Frida + gdb — for dynamic execution / emulation / AI code-gen.
#
# Runtime hardening (applied in tools/sandbox.py when spawning):
#   --network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges
#   --memory=2g --cpus=2 --tmpfs /scratch:rw,noexec,nosuid,nodev --pids-limit=256

FROM python:3.11-slim AS base

# Minimal system libs; no interactive prompts.
RUN apt-get update && apt-get install -y --no-install-recommends \
      git curl ca-certificates libgomp1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work

# Install the project (core deps) so sandboxed code can import agent/tools.
COPY pyproject.toml README.md ./
COPY agent ./agent
COPY mcp_servers ./mcp_servers
COPY tools ./tools
RUN python -m pip install --no-cache-dir -e ".[dev]"

# Code-gen runner: the agent writes a Python file into /scratch, this runs it and
# prints its JSON result on stdout (read back by tools/sandbox.py).
COPY docker/codegen_runner.py /usr/local/bin/codegen_runner.py
RUN chmod +x /usr/local/bin/codegen_runner.py

# ---------------- core tier ----------------
FROM base AS core
RUN echo "core tier: static + malware + agent tools (no binary execution engines)" > /etc/tier
ENTRYPOINT ["python", "/usr/local/bin/codegen_runner.py"]

# ---------------- full tier ----------------
FROM base AS full
# Heavy execution / emulation / symbolic engines. Failures degrade gracefully
# (engines auto-detected and skipped if unavailable).
RUN python -m pip install --no-cache-dir \
      "angr>=9.2" "qiling>=1.5" "unicorn>=2.0" \
      "frida>=16.5" "frida-tools>=12.4" \
      "capa>=7.0" || true
RUN apt-get update && apt-get install -y --no-install-recommends \
      gdb yara \
    && rm -rf /var/lib/apt/lists/* || true
RUN echo "full tier: core + angr + qiling + frida + gdb + capa" > /etc/tier
ENTRYPOINT ["python", "/usr/local/bin/codegen_runner.py"]
