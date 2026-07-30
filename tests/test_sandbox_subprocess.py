"""Tests for the opt-in restricted-subprocess isolation backend in tools/sandbox.py.

This backend is the WEAK-isolation fallback used only when Docker is unavailable
AND the user has explicitly opted in. It is NOT a security boundary on par with
Docker (Windows cannot truly drop capabilities / enforce read-only mounts), so
the tests assert the *best-effort* isolation properties we DO control:
  - runs in a throwaway temp scratch dir (never the caller's cwd)
  - the target is a COPY, so the original file is never read/written by the child
  - env is scrubbed: a leaked parent env var is NOT visible to the child
  - stdin is DEVNULL
  - hard timeout kills a runaway child and reports timed_out
  - stdout/stderr captured (bounded), exit_code returned
"""
from __future__ import annotations

import os
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

import tools.sandbox as sandbox  # noqa: E402


def _write(p: Path, body: str) -> Path:
    p.write_text(textwrap.dedent(body))
    return p


# ---------------------------------------------------------------------------
# Runs in a throwaway scratch dir + target is a copy (original untouched)
# ---------------------------------------------------------------------------
def test_runs_in_scratch_and_does_not_touch_original(tmp_path):
    orig = _write(tmp_path / "tgt.py", """
        import os
        print("CWD=" + os.getcwd())
        open("marker.txt", "w").write("written-in-child")
        print("OK_OUT")
    """)
    before = orig.read_text()

    res = sandbox.run_restricted_subprocess(
        [sys.executable, "-I", "tgt.py"], scratch_files=[orig], timeout=15,
        keep_scratch=True,
        allow_host_fallback=True,
    )

    assert res["ok"] is True
    assert res["exit_code"] == 0
    assert "OK_OUT" in res["stdout"]
    # the child's cwd is the scratch dir, not tmp_path
    scratch = Path(res["scratch"])
    assert scratch != tmp_path
    assert "CWD=" + str(scratch) in res["stdout"]
    # the marker was written inside scratch, never in tmp_path
    assert (scratch / "marker.txt").exists()
    assert not (tmp_path / "marker.txt").exists()
    # the original file content is unchanged
    assert orig.read_text() == before


# ---------------------------------------------------------------------------
# Env is scrubbed: a leaked parent env var must NOT reach the child
# ---------------------------------------------------------------------------
def test_parent_env_var_does_not_leak(tmp_path, monkeypatch):
    monkeypatch.setenv("RE_LEAK_SECRET", "super-secret-value")
    probe = _write(tmp_path / "probe.py", """
        import os
        print("LEAK=" + os.environ.get("RE_LEAK_SECRET", "NONE"))
    """)
    res = sandbox.run_restricted_subprocess(
        [sys.executable, "-I", "probe.py"], scratch_files=[probe], timeout=15,
        allow_host_fallback=True,
    )
    assert res["ok"] is True
    assert "LEAK=NONE" in res["stdout"]
    assert "super-secret-value" not in res["stdout"]


def test_explicit_extra_env_is_injected(tmp_path):
    probe = _write(tmp_path / "probe.py", """
        import os
        print("ALLOW=" + os.environ.get("RE_ALLOWED", "MISSING"))
    """)
    res = sandbox.run_restricted_subprocess(
        [sys.executable, "-I", "probe.py"], scratch_files=[probe], timeout=15,
        extra_env={"RE_ALLOWED": "yes"},
        allow_host_fallback=True,
    )
    assert res["ok"] is True
    assert "ALLOW=yes" in res["stdout"]


# ---------------------------------------------------------------------------
# stdin is DEVNULL: a child that blocks on stdin is killed by the timeout
# ---------------------------------------------------------------------------
def test_stdin_is_devnull(tmp_path):
    reader = _write(tmp_path / "reader.py", """
        import sys
        data = sys.stdin.read()  # would block forever if stdin were a tty/pipe
        print("GOT=" + repr(data))
    """)
    # stdin DEVNULL -> read returns "" immediately, prints GOT=''
    res = sandbox.run_restricted_subprocess(
        [sys.executable, "-I", "reader.py"], scratch_files=[reader], timeout=15,
        allow_host_fallback=True,
    )
    assert res["ok"] is True
    assert "GOT=''" in res["stdout"]


# ---------------------------------------------------------------------------
# Hard timeout kills a runaway child
# ---------------------------------------------------------------------------
def test_timeout_kills_runaway_child(tmp_path):
    sleeper = _write(tmp_path / "sleep.py", """
        import time
        print("START", flush=True)
        time.sleep(30)
        print("END", flush=True)
    """)
    res = sandbox.run_restricted_subprocess(
        [sys.executable, "-I", "sleep.py"], scratch_files=[sleeper], timeout=2,
        allow_host_fallback=True,
    )
    assert res["ok"] is False
    assert res["timed_out"] is True
    # stdout captured up to the kill point
    assert "START" in res["stdout"]
    assert "END" not in res["stdout"]


# ---------------------------------------------------------------------------
# stderr + non-zero exit captured
# ---------------------------------------------------------------------------
def test_stderr_and_exit_code_captured(tmp_path):
    failer = _write(tmp_path / "fail.py", """
        import sys
        sys.stderr.write("ERRLINE\\n")
        sys.exit(7)
    """)
    res = sandbox.run_restricted_subprocess(
        [sys.executable, "-I", "fail.py"], scratch_files=[failer], timeout=15,
        allow_host_fallback=True,
    )
    assert res["ok"] is False
    assert res["exit_code"] == 7
    assert "ERRLINE" in res["stderr"]


# ---------------------------------------------------------------------------
# Output is bounded (huge stdout truncated, no memory blowup)
# ---------------------------------------------------------------------------
def test_output_is_bounded(tmp_path):
    puker = _write(tmp_path / "puker.py", """
        print("X" * 1_000_000)
    """)
    res = sandbox.run_restricted_subprocess(
        [sys.executable, "-I", "puker.py"], scratch_files=[puker], timeout=20,
        max_output=1024,
        allow_host_fallback=True,
    )
    assert len(res["stdout"]) <= 1024 + 100  # allow truncation suffix
    assert res.get("stdout_truncated") is True


# ---------------------------------------------------------------------------
# Opt-in gate: refuses by default unless allow_host_fallback=True
# ---------------------------------------------------------------------------
def test_refuses_without_opt_in(tmp_path):
    tgt = _write(tmp_path / "t.py", "print('no')")
    with pytest.raises(sandbox.SandboxUnavailableError):
        sandbox.run_restricted_subprocess([sys.executable, "t.py"], scratch_files=[tgt])


def test_opt_in_runs(tmp_path):
    tgt = _write(tmp_path / "t.py", "print('yes')")
    res = sandbox.run_restricted_subprocess(
        [sys.executable, "-I", "t.py"], scratch_files=[tgt], timeout=15,
        allow_host_fallback=True,
    )
    assert res["ok"] is True
    assert "yes" in res["stdout"]


# ---------------------------------------------------------------------------
# Scratch dir is cleaned up after the run
# ---------------------------------------------------------------------------
def test_scratch_dir_cleaned_up(tmp_path):
    tgt = _write(tmp_path / "t.py", "open('child.txt','w').write('x')")
    res = sandbox.run_restricted_subprocess(
        [sys.executable, "-I", "t.py"], scratch_files=[tgt], timeout=15,
        allow_host_fallback=True,
    )
    scratch = Path(res["scratch"])
    assert res["ok"] is True
    assert not scratch.exists()  # cleaned up
