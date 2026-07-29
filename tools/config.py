"""Configuration loading with default merging.

Loads a YAML config (default: config/config.yaml, or RE_CONFIG env, or an explicit path)
deep-merged over built-in defaults. Resolves llm.api_key from the env var named by
llm.api_key_env. Keeps a single module-level CONFIG after first load.
"""
from __future__ import annotations

import copy
import os
from pathlib import Path

import yaml

# Built-in defaults — mirrors config/config.example.yaml. Keep these in sync.
_DEFAULTS: dict = {
    "llm": {
        "provider": "openai",
        "model": "gpt-4o-mini",
        "api_key_env": "OPENAI_API_KEY",
        "temperature": 0.2,
        "max_tokens": 4096,
        "timeout": 120,
    },
    "specialists": {
        n: {"model": ""} for n in
        ("static", "dynamic", "symbolic", "deobfuscation", "malware", "supervisor")
    },
    "mcp": {
        "servers": {
            "static":        {"command": "python", "args": ["-m", "mcp_servers.static.server"]},
            "dynamic":       {"command": "python", "args": ["-m", "mcp_servers.dynamic.server"]},
            "symbolic":      {"command": "python", "args": ["-m", "mcp_servers.symbolic.server"]},
            "deobfuscation": {"command": "python", "args": ["-m", "mcp_servers.deobfuscation.server"]},
            "malware":       {"command": "python", "args": ["-m", "mcp_servers.malware.server"]},
        },
        "tool_timeout": 120,
    },
    "safety": {
        "require_confirmation": True,
        "refuse_high_risk": True,
        "sandbox_image_core": "re-agent:core",
        "sandbox_image_full": "re-agent:full",
        "docker_unavailable_fallback": "static_only",
    },
    "engines": {
        n: {"enabled": "auto"} for n in
        ("ghidra", "radare2", "angr", "frida", "qiling", "capstone", "capa", "yara", "binwalk")
    },
    "workflow": {
        "max_adaptations": 8,
        "persist_playbooks": True,
        "codegen_dir": ".codegen",
        "symbolic_state_budget": 50000,
    },
    "state": {"workspace_dir": "sessions", "log_dir": "logs"},
}

# Cached merged config (after first load).
_CONFIG: dict | None = None


def defaults() -> dict:
    """Return a deep copy of the built-in defaults."""
    return copy.deepcopy(_DEFAULTS)


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge `override` into `base` (override wins); returns a new dict."""
    result = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _resolve_api_key(conf: dict) -> dict:
    env_name = conf.get("llm", {}).get("api_key_env", "")
    if env_name:
        val = os.environ.get(env_name, "")
        if val:
            conf["llm"]["api_key"] = val
    return conf


def load(path: str | Path | None = None, *, refresh: bool = False) -> dict:
    """Load config: defaults deep-merged with the YAML at `path` (if it exists).

    If `path` is None, falls back to the RE_CONFIG env var, then config/config.yaml.
    Results are cached unless `refresh=True`.
    """
    global _CONFIG
    if _CONFIG is not None and not refresh and path is None:
        return _CONFIG

    p = Path(path) if path else Path(os.environ.get("RE_CONFIG", "config/config.yaml"))
    conf = defaults()
    if p.is_file():
        with open(p, "r", encoding="utf-8") as f:
            user = yaml.safe_load(f) or {}
        conf = _deep_merge(conf, user)

    conf = _resolve_api_key(conf)
    if path is None:
        _CONFIG = conf
    return conf


def get() -> dict:
    """Return the cached config, loading it if not yet loaded."""
    if _CONFIG is None:
        return load()
    return _CONFIG
