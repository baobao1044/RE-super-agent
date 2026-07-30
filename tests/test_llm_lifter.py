"""Tests for the agentic LLM decompiler in tools/llm_lifter.py.

The LLM lifter uses the configured LLM provider (GLM-5.2 via W&B by default) to
translate the custom structural lifter's bytecode annotations into real Python
source (if/for/comprehension instead of `# RERAISE` comments). Tests inject a
fake completion_fn so no network is required.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
TESTS = ROOT / "tests"
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

import tools.llm_lifter as ll  # noqa: E402
from tools.decompile_lifter import reconstruct_source  # noqa: E402


def _compile(body: str):
    import textwrap
    return compile(textwrap.dedent(body), "<test>", "exec")


class _FakeResp:
    def __init__(self, content):
        self.choices = [type("C", (), {"message": type("M", (), {"content": content})(),
                                        "finish_reason": "stop"})()]


def _fake_completion(real_source):
    """Return a completion_fn that yields real_source as the assistant content."""
    def fn(**kwargs):
        return _FakeResp(real_source)
    return fn


# ---------------------------------------------------------------------------
# llm_decompile: structural source -> LLM -> real Python source
# ---------------------------------------------------------------------------
def test_llm_decompile_translates_bytecode_to_real_source(tmp_path):
    """A scope with if/for is translated by the LLM into real control-flow source."""
    co = _compile("""
        def add(a, b):
            if a > 0:
                return a + b
            return 0
    """)
    structural = reconstruct_source(co)
    real = "def add(a, b):\n    if a > 0:\n        return a + b\n    return 0\n"
    provider = type("P", (), {"complete": lambda self, **k: type(
        "R", (), {"content": real, "stop_reason": "stop"})()})()
    out = ll.llm_decompile(structural, provider=provider)
    assert "if a > 0" in out
    assert "return a + b" in out


def test_llm_decompile_falls_back_when_no_provider(tmp_path):
    """Without a provider, return the structural source unchanged (safe fallback)."""
    co = _compile("def f(): return 1")
    structural = reconstruct_source(co)
    out = ll.llm_decompile(structural, provider=None)
    assert out == structural


def test_llm_decompile_falls_back_on_llm_error(tmp_path):
    """If the LLM raises or returns empty, return the structural source."""
    co = _compile("def f(): return 1")
    structural = reconstruct_source(co)
    provider = type("P", (), {"complete": lambda self, **k: type(
        "R", (), {"content": "", "stop_reason": "error"})()})()
    out = ll.llm_decompile(structural, provider=provider)
    assert out == structural  # fallback to structural


def test_llm_decompile_falls_back_on_exception(tmp_path):
    """If the provider raises, return structural source (never crash)."""
    co = _compile("def f(): return 1")
    structural = reconstruct_source(co)
    provider = type("P", (), {"complete": lambda self, **k: (_ for _ in ()).throw(RuntimeError("boom"))})()
    out = ll.llm_decompile(structural, provider=provider)
    assert out == structural


def test_llm_decompile_truncates_large_structural():
    """Very large structural input is truncated before sending to the LLM (context budget)."""
    big = "# === scope ===\n" + "# 0 NOP\n" * 50000
    provider = type("P", (), {})()
    seen = {}
    def fake_complete(self, messages, **kw):
        seen["len"] = len(messages[0]["content"])
        return type("R", (), {"content": "def f(): pass\n", "stop_reason": "stop"})()
    provider.complete = fake_complete.__get__(provider)
    out = ll.llm_decompile(big, provider=provider, max_struct_chars=2000)
    assert seen["len"] <= 2200  # truncated + suffix


def test_llm_decompile_passes_version_context():
    """Optional python_version hint is included in the LLM prompt."""
    co = _compile("def f(): return 1")
    structural = reconstruct_source(co)
    seen = {}
    provider = type("P", (), {})()
    def fake_complete(self, messages, **kw):
        seen["prompt"] = messages[0]["content"]
        return type("R", (), {"content": "def f(): return 1\n", "stop_reason": "stop"})()
    provider.complete = fake_complete.__get__(provider)
    ll.llm_decompile(structural, provider=provider, python_version=(3, 11))
    assert "3.11" in seen["prompt"]


PROTECTED = ROOT / "protected_deobfuscated_app.py"


@pytest.mark.skipif(not PROTECTED.exists(), reason="no protected sample")
def test_decompile_python_source_with_llm_on_protected_sample(tmp_path):
    """End-to-end on the protected sample using a fake LLM that echoes real source."""
    from tools.decompile_lifter import decompile_python_source as _orig
    # Provide a fake provider that returns plausible real source
    real_src = "def add(a, b):\n    if a > 0:\n        return a + b\n    return 0\n"
    provider = type("P", (), {"complete": lambda self, **k: type(
        "R", (), {"content": real_src, "stop_reason": "stop"})()})()
    res = ll.decompile_python_source_with_llm(str(PROTECTED), provider=provider)
    assert res["available"] is True
    assert "if a > 0" in res["source"]
    assert res["decompiler"] == "llm-lifter"


def test_decompile_python_source_with_llm_missing_file(tmp_path):
    res = ll.decompile_python_source_with_llm(str(tmp_path / "nope.py"), provider=None)
    assert res["available"] is False
    assert "not found" in res.get("error", "").lower()
