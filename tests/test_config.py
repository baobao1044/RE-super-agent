"""Tests for tools/config.py — config loading + default merging."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import config as cfg  # noqa: E402


def test_defaults_have_required_sections():
    c = cfg.defaults()
    assert "llm" in c and "model" in c["llm"]
    assert "mcp" in c and "servers" in c["mcp"]
    assert "safety" in c
    assert "workflow" in c


def test_load_missing_file_returns_defaults():
    c = cfg.load(Path("/nonexistent/path/config.yaml"))
    assert c["llm"]["model"] == cfg.defaults()["llm"]["model"]


def test_user_overrides_defaults(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("llm:\n  model: claude-3-5-sonnet\n  temperature: 0.5\n")
    c = cfg.load(p)
    # overridden values
    assert c["llm"]["model"] == "claude-3-5-sonnet"
    assert c["llm"]["temperature"] == 0.5
    # non-overridden defaults preserved (deep merge)
    assert c["llm"]["max_tokens"] == cfg.defaults()["llm"]["max_tokens"]
    assert "mcp" in c  # untouched section still present


def test_env_overrides_api_key_env(monkeypatch, tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("llm:\n  api_key_env: MY_KEY\n")
    monkeypatch.setenv("MY_KEY", "secret123")
    c = cfg.load(p)
    assert c["llm"]["api_key"] == "secret123"


def test_deep_merge_does_not_clobber_nested(tmp_path):
    p = tmp_path / "c.yaml"
    # only override one server; others must remain
    p.write_text("mcp:\n  servers:\n    static:\n      command: rizin\n")
    c = cfg.load(p)
    assert c["mcp"]["servers"]["static"]["command"] == "rizin"
    assert "dynamic" in c["mcp"]["servers"]  # default sibling preserved
