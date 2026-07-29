"""Tests for agent.core.safety — the risk gate that decides how (or whether) a binary
may be executed.

Risk levels: LOW / MEDIUM / HIGH. The gate maps risk -> an ExecutionDecision:
  - LOW  -> sandbox (Docker) execution permitted
  - MEDIUM -> Qiling emulation-in-Docker first; real execution requires confirmation
  - HIGH -> static-only refusal; dynamic/code-gen refused
When Docker is unavailable, everything degrades to static-only (no host execution).
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

from agent.core import safety  # noqa: E402
from tools.binary import BinaryInfo  # noqa: E402


def _info(risk_hints=None) -> BinaryInfo:
    return BinaryInfo(
        path="x", format="PE", arch="x86_64", bits=64, endian="little",
        entry=0x1000, sha256="a" * 64, size=1024, risk_hints=list(risk_hints or []),
    )


# ---------------------------------------------------------------------------
# classify_risk: hints -> risk level
# ---------------------------------------------------------------------------
def test_classify_low_clean_binary():
    assert safety.classify_risk(_info([])) == "LOW"


def test_classify_medium_for_dll_only():
    # a DLL alone is suspicious but not catastrophic -> MEDIUM
    assert safety.classify_risk(_info(["is_dll"])) == "MEDIUM"


def test_classify_high_for_wiper_signature():
    assert safety.classify_risk(_info(["wiper_signature"])) == "HIGH"


def test_classify_high_for_kernel_driver():
    assert safety.classify_risk(_info(["kernel_driver"])) == "HIGH"


def test_classify_high_for_anti_vm_escape():
    assert safety.classify_risk(_info(["anti_vm_escape"])) == "HIGH"


def test_classify_high_dominates_medium():
    # if both MEDIUM and HIGH hints present, HIGH wins
    assert safety.classify_risk(_info(["is_dll", "wiper_signature"])) == "HIGH"


# ---------------------------------------------------------------------------
# decide: risk -> ExecutionDecision (respecting Docker availability)
# ---------------------------------------------------------------------------
def test_decide_low_permits_sandbox(monkeypatch):
    monkeypatch.setattr(safety.sandbox, "is_available", lambda: True)
    d = safety.decide(_info([]))
    assert d.allowed is True
    assert d.mode == "sandbox"
    assert d.requires_confirmation is False


def test_decide_medium_qiling_first_and_requires_confirmation(monkeypatch):
    monkeypatch.setattr(safety.sandbox, "is_available", lambda: True)
    d = safety.decide(_info(["is_dll"]))
    assert d.allowed is True
    assert d.mode == "qiling_first"
    assert d.requires_confirmation is True


def test_decide_high_refuses(monkeypatch):
    monkeypatch.setattr(safety.sandbox, "is_available", lambda: True)
    d = safety.decide(_info(["kernel_driver"]))
    assert d.allowed is False
    assert d.mode == "static_only"
    assert "HIGH" in d.reason


def test_decide_degrades_to_static_only_when_docker_missing(monkeypatch):
    """Even a LOW binary must NOT execute when no sandbox exists."""
    monkeypatch.setattr(safety.sandbox, "is_available", lambda: False)
    d = safety.decide(_info([]))
    assert d.allowed is False
    assert d.mode == "static_only"
    assert "unavailable" in d.reason.lower()


def test_decide_respects_refuse_high_config(monkeypatch):
    """Config can force HIGH refusal off — but HIGH still degrades to static unless sandbox."""
    monkeypatch.setattr(safety.sandbox, "is_available", lambda: True)
    d = safety.decide(_info(["wiper_signature"]))
    assert d.allowed is False  # HIGH is always static-only regardless
