"""Tests for mcp_servers.symbolic.angr_backend — symbolic execution + constraint solving.

angr is NOT installed here, so angr-backed ops degrade to available=False. But the
backend includes a small pure-python constraint solver (z3-free, brute-force over a
bounded input) so find_input_satisfying / extract_flag can be tested deterministically
for tiny problems. Tests cover both the degrade path and the pure solver.
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

from mcp_servers.symbolic import angr_backend  # noqa: E402


def _force_unavailable(monkeypatch, modname):
    import builtins
    real = builtins.__import__

    def fake(name, *a, **k):
        if name == modname:
            raise ImportError(f"no {modname}")
        return real(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake)


# ---------------------------------------------------------------------------
# angr-backed ops degrade
# ---------------------------------------------------------------------------
def test_load_project_unavailable(monkeypatch, tmp_path):
    _force_unavailable(monkeypatch, "angr")
    res = angr_backend.load_project(str(tmp_path / "x.elf"))
    assert res["available"] is False
    assert "error" in res


def test_explore_to_unavailable(monkeypatch, tmp_path):
    _force_unavailable(monkeypatch, "angr")
    res = angr_backend.explore_to(str(tmp_path / "x.elf"), target_addr=0x401000)
    assert res["available"] is False


def test_get_state_info_unavailable(monkeypatch, tmp_path):
    _force_unavailable(monkeypatch, "angr")
    res = angr_backend.get_state_info(str(tmp_path / "x.elf"))
    assert res["available"] is False


# ---------------------------------------------------------------------------
# pure-python constraint solver (always available, deterministic)
# ---------------------------------------------------------------------------
def test_find_input_satisfying_pure_solver_match():
    """find an input satisfying a simple predicate: x == 42."""
    def predicate(x: bytes) -> bool:
        return len(x) == 1 and x[0] == 42

    res = angr_backend.find_input_satisfying(
        predicate=predicate, input_length=1, max_value=256, use_angr=False)
    assert res["found"] is True
    assert res["input"] == [42]


def test_find_input_satisfying_pure_solver_no_match():
    def predicate(x: bytes) -> bool:
        return x == b"\xff\xff"

    # alphabet 0..9 (2-byte input) never equals \xff\xff -> not found
    res = angr_backend.find_input_satisfying(
        predicate=predicate, input_length=2, alphabet=range(10), use_angr=False)
    assert res["found"] is False


def test_extract_flag_with_predicate():
    """extract_flag walks a tiny alphabet for a 3-byte flag (deterministic)."""
    secret = b"CAT"

    def flag_predicate(x: bytes) -> bool:
        return x == secret

    res = angr_backend.extract_flag(
        flag_predicate=flag_predicate, expected_len=3,
        alphabet=range(65, 91),  # A..Z
        use_angr=False)
    assert res["found"] is True
    assert res["flag"] == secret.decode()


def test_extract_flag_not_found():
    def flag_predicate(x: bytes) -> bool:
        return False

    res = angr_backend.extract_flag(
        flag_predicate=flag_predicate, expected_len=2, alphabet=range(65, 91),
        use_angr=False, search_depth=50)
    assert res["found"] is False


def test_angr_fallback_to_pure_solver_when_unavailable(monkeypatch):
    """find_input_satisfying with use_angr=True must fall back to pure solver if angr absent."""
    _force_unavailable(monkeypatch, "angr")

    def predicate(x: bytes) -> bool:
        return x == b"AB"

    res = angr_backend.find_input_satisfying(
        predicate=predicate, input_length=2, max_value=256, use_angr=True,
        alphabet=range(65, 91))
    assert res["found"] is True
    assert res["input"] == [65, 66]
    assert res["engine"] == "pure_solver"
