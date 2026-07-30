"""Tests for the custom bytecode->source lifter in tools/eps_deobf.py.

Since no installed decompiler supports Python 3.11 (uncompyle6/decompyle3 refuse 3.11,
zrax pycdc needs a C++ build toolchain that is absent), eps_deobf ships a structural
decompiler that walks the recovered code objects and emits readable Python source.

Covers: reconstruct_source() on module/function/class/arg variants, and the
end-to-end decompile_python_source() on a protected target.
"""
from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
TESTS = ROOT / "tests"
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from tools.decompile_lifter import reconstruct_source, decompile_python_source  # noqa: E402


def _compile(body: str):
    """Compile a module source and return its top-level code object."""
    return compile(textwrap.dedent(body), "<test>", "exec")


# ---------------------------------------------------------------------------
# Module-level structure: function/class definitions + simple assignments
# ---------------------------------------------------------------------------
def test_reconstruct_function_definition():
    co = _compile("""
        def add(a, b):
            return a + b
    """)
    src = reconstruct_source(co)
    assert "def add" in src
    assert "a" in src and "b" in src


def test_reconstruct_class_definition_with_base():
    co = _compile("""
        class MyError(Exception):
            pass
    """)
    src = reconstruct_source(co)
    assert "class MyError" in src
    assert "Exception" in src


def test_reconstruct_simple_constant_assignment():
    co = _compile("""
        X = 42
        NAME = "hello"
    """)
    src = reconstruct_source(co)
    assert "X = 42" in src
    assert "hello" in src


# ---------------------------------------------------------------------------
# Function signatures: args, *args, **kwargs, defaults
# ---------------------------------------------------------------------------
def test_reconstruct_varargs_signature():
    co = _compile("""
        def f(a, b, *args, **kwargs):
            return a
    """)
    src = reconstruct_source(co)
    assert "*args" in src
    assert "**kwargs" in src


def test_reconstruct_nested_scopes_recursed():
    co = _compile("""
        def outer(x):
            def inner(y):
                return y
            return inner
    """)
    src = reconstruct_source(co)
    assert "def outer" in src
    assert "def inner" in src


# ---------------------------------------------------------------------------
# Fallback: unknown bytecode is emitted as an annotated comment, not dropped
# ---------------------------------------------------------------------------
def test_reconstruct_falls_back_to_comment_for_complex_body():
    # A loop is complex enough that the lifter annotates rather than guessing wrong.
    co = _compile("""
        def count():
            total = 0
            for i in range(10):
                total += i
            return total
    """)
    src = reconstruct_source(co)
    assert "def count" in src
    # the body must contain SOME annotation of the bytecode (a `#` comment with an opname)
    assert any(ln.lstrip().startswith("#") and any(
        op in ln for op in ("FOR_ITER", "INPLACE_ADD", "LOAD_FAST", "STORE_FAST", "JUMP"))
        for ln in src.splitlines())


# ---------------------------------------------------------------------------
# End-to-end on the protected sample
# ---------------------------------------------------------------------------
PROTECTED = ROOT / "protected_deobfuscated_app.py"


@pytest.mark.skipif(not PROTECTED.exists(), reason="no protected sample to decompile")
def test_decompile_python_source_on_protected_sample():
    res = decompile_python_source(str(PROTECTED))
    assert res["available"] is True
    assert isinstance(res["source"], str)
    assert len(res["source"]) > 0
    # The recovered source must show recognizable Python structure
    assert ("def " in res["source"]) or ("class " in res["source"]) or ("lambda" in res["source"].lower())
    assert "decompiler" in res


def test_decompile_python_source_missing_file(tmp_path):
    res = decompile_python_source(str(tmp_path / "nonexistent.py"))
    assert res["available"] is False
    assert "not found" in res.get("error", "").lower()
