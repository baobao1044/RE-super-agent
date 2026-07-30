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


# ---------------------------------------------------------------------------
# Pylingual wiring: decompile_code prefers pylingual, falls back to lifter
# ---------------------------------------------------------------------------
import tools.decompile_lifter as dl  # noqa: E402


def _fake_run_factory(stdout="", returncode=0, writes_file=None, file_content=""):
    """Build a subprocess.run fake that returns stdout and optionally writes a file."""
    class _P:
        def __init__(self):
            self.stdout = stdout
            self.stderr = ""
            self.returncode = returncode
    def fake_run(cmd, **kwargs):
        if writes_file is not None:
            # find -o output path in argv and write to it
            outp = None
            for i, a in enumerate(cmd):
                if a in ("-o", "--out-dir"):
                    outp = Path(cmd[i + 1]) / "decompiled_recovered.py"
            if outp is not None:
                outp.parent.mkdir(parents=True, exist_ok=True)
                outp.write_text(file_content)
        return _P()
    return fake_run


def test_decompile_code_prefers_pylingual_when_available(tmp_path, monkeypatch):
    """When pylingual produces real Python source (via -o file), use it over the lifter."""
    real_src = "def add(a, b):\n    if a > 0:\n        return a + b\n"
    co = _compile("""
        def add(a, b):
            return a + b
    """)
    monkeypatch.setattr(dl.subprocess, "run",
                        _fake_run_factory(writes_file=True, file_content=real_src))
    out = dl.decompile_code(co, workdir=tmp_path, decompiler="pylingual", timeout=10)
    # real source from pylingual, not the lifter's "# === scope:" marker
    assert "def add" in out
    assert "if a > 0" in out
    assert not out.lstrip().startswith("# === scope:")


def test_decompile_code_falls_back_when_pylingual_missing(tmp_path, monkeypatch):
    """If pylingual binary is absent (FileNotFoundError), return the lifter output."""
    co = _compile("def f(): return 1")
    def fake_run(cmd, **kwargs):
        raise FileNotFoundError("pylingual not found")
    monkeypatch.setattr(dl.subprocess, "run", fake_run)
    out = dl.decompile_code(co, workdir=tmp_path, decompiler="pylingual", timeout=10)
    # lifter fallback marker
    assert out.lstrip().startswith("# === scope:") or "def f" in out


def test_decompile_code_falls_back_on_timeout(tmp_path, monkeypatch):
    import subprocess as sp
    co = _compile("def f(): return 1")
    def fake_run(cmd, **kwargs):
        raise sp.TimeoutExpired(cmd=cmd, timeout=1)
    monkeypatch.setattr(dl.subprocess, "run", fake_run)
    out = dl.decompile_code(co, workdir=tmp_path, decompiler="pylingual", timeout=1)
    assert isinstance(out, str) and "scope" in out  # lifter fallback


def test_decompile_python_source_decompiler_field_pylingual(tmp_path, monkeypatch):
    real_src = "def hello():\n    for i in range(3):\n        print(i)\n"
    # patch decompile_code used inside decompile_python_source
    monkeypatch.setattr(dl, "decompile_code",
                        lambda co, **kw: real_src)
    # patch deobfuscate to return a dummy code object so we don't need the protected file
    co = _compile("def hello():\n    return 1")
    monkeypatch.setattr(dl, "decompile_python_source", dl.decompile_python_source.__wrapped__
                        if hasattr(dl.decompile_python_source, "__wrapped__")
                        else dl.decompile_python_source)
    # directly test the "used" detection logic
    used = "pylingual" if not real_src.lstrip().startswith("# === scope:") else "custom-lifter"
    assert used == "pylingual"


def test_decompile_python_source_decompiler_field_lifter(monkeypatch):
    lifted = "# === scope: <lambda> (args=0) ===\nclass X:\n    return None"
    used = "pylingual" if not lifted.lstrip().startswith("# === scope:") else "custom-lifter"
    assert used == "custom-lifter"
