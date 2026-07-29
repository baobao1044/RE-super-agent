"""Docker sandbox: the ONLY place untrusted code/binaries are executed.

Responsibilities:
- Detect whether the Docker daemon + SDK are available (cached).
- Spawn a hardened container to run AI-generated code snippets (code-gen workflow nodes)
  and (later) dynamic execution / Qiling emulation.
- Parse the codegen_runner.py JSON result from stdout.
- NEVER fall back to running on the host: if Docker is unavailable, refuse with
  SandboxUnavailableError so the safety layer can degrade to static-only.

Runtime hardening applied to every run():
  network_disabled=True  read_only=True  cap_drop=["ALL"]
  mem_limit="2g"  nano_cpus=2 cores  pids_limit=256  security_opt=no-new-privileges
  tmpfs /scratch (noexec,nosuid,nodev)  working_dir=/scratch
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

log = logging.getLogger(__name__)

# Cached availability probe result: None = not probed yet; True/False after probe.
_available_cache: bool | None = None


class SandboxUnavailableError(RuntimeError):
    """Raised when execution is requested but no Docker sandbox is available.

    The safety layer must catch this and degrade to static-only — never to host exec.
    """


def is_available() -> bool:
    """Return True if the docker SDK can import AND a daemon responds."""
    global _available_cache
    if _available_cache is not None:
        return _available_cache
    try:
        import docker  # type: ignore  # noqa: F401
    except Exception:  # noqa: BLE001
        _available_cache = False
        return False
    try:
        client = docker.from_env()  # type: ignore[attr-defined]
        client.ping()
        _available_cache = True
    except Exception:  # noqa: BLE001 — daemon may not be running
        _available_cache = False
    return _available_cache


def _get_raw_client():
    """Return a fresh docker client. (Tests monkeypatch this to inject a fake.)"""
    import docker  # type: ignore

    return docker.from_env()


def get_client():
    """Return a docker client, or raise if unavailable."""
    if not is_available():
        raise SandboxUnavailableError("Docker sandbox unavailable")
    return _get_raw_client()


# ---------------------------------------------------------------------------
# Hardened container run
# ---------------------------------------------------------------------------
def _hardening_kwargs() -> dict:
    """The isolation flags applied to EVERY sandboxed run."""
    return {
        "network_disabled": True,          # --network=none
        "read_only": True,                 # --read-only
        "cap_drop": ["ALL"],               # --cap-drop=ALL
        "security_opt": ["no-new-privileges"],
        "mem_limit": "2g",                 # --memory=2g
        "nano_cpus": 2_000_000_000,        # ~2 cpus
        "pids_limit": 256,
        "tmpfs": {"/scratch": "rw,noexec,nosuid,nodev,size=512m"},
        "working_dir": "/scratch",
    }


def run_codegen(
    script_path: str | Path,
    *,
    image: str = "re-agent:full",
    input_path: str | Path | None = None,
    timeout: int = 120,
) -> dict:
    """Run an AI-generated Python snippet inside the sandbox and return its JSON result.

    The snippet is bind-mounted (not copied) and executed by the image's
    codegen_runner.py entrypoint. Returns a dict with keys: ok, result, exit_code.

    Raises SandboxUnavailableError if Docker is not available — never executes on host.
    """
    if not is_available():
        raise SandboxUnavailableError("Docker sandbox unavailable; refusing to run code on host")

    script_path = Path(script_path)
    client = get_client()
    kw = _hardening_kwargs()

    # Bind-mount the script (and optional input) read-only into /scratch.
    host_script = str(script_path.resolve())
    guest_script = "/scratch/snippet.py"
    volumes = {host_script: {"bind": guest_script, "mode": "ro"}}
    guest_input: str | None = None
    if input_path is not None:
        host_input = str(Path(input_path).resolve())
        guest_input = "/scratch/input.json"
        volumes[host_input] = {"bind": guest_input, "mode": "ro"}
    kw["volumes"] = volumes

    command = ["python", "/usr/local/bin/codegen_runner.py", guest_script]
    if guest_input is not None:
        command.append(guest_input)

    log.info("sandbox run_codegen image=%s timeout=%ss", image, timeout)
    container = client.run(image, command, **kw)
    exit_info = container.wait()
    exit_code = int(exit_info.get("StatusCode", 0)) if isinstance(exit_info, dict) else 0
    raw = container.logs()
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")

    try:
        parsed = json.loads(raw)
    except Exception:  # noqa: BLE001
        parsed = {"ok": False, "error": f"non-json stdout: {raw[:200]}", "raw": raw}

    if exit_code != 0:
        parsed["ok"] = False
        parsed["exit_code"] = exit_code
    elif "exit_code" not in parsed:
        parsed.setdefault("exit_code", exit_code)
    return parsed


# ---------------------------------------------------------------------------
# Risk -> environment selection
# ---------------------------------------------------------------------------
def environment_for_risk(risk_level: str, *, require_full: bool = False) -> str | None:
    """Pick a sandbox image based on risk level.

    Returns None for HIGH (no execution permitted) and when Docker is unavailable.
    """
    if not is_available():
        return None
    risk = (risk_level or "").upper()
    if risk == "HIGH":
        return None
    if risk == "MEDIUM" or require_full:
        return "re-agent:full"
    # LOW (or unknown) -> lightweight core tier
    return "re-agent:core"
