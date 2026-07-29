"""Tests wiring the malware risk assessment into the safety gate.

safety.decide() can now take a risk_assessment (from risk_policy/malware specialist)
and use it authoritatively, instead of only re-classifying from BinaryInfo.risk_hints.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent.core import safety  # noqa: E402
from tools.binary import BinaryInfo  # noqa: E402


def _info():
    return BinaryInfo(
        path="x", format="PE", arch="x86_64", bits=64, endian="little",
        entry=0x1000, sha256="a" * 64, size=1024, risk_hints=[],
    )


def _assess(level, hints):
    return {
        "risk_level": level,
        "risk_hints": list(hints),
        "recommendation": {"mode": "static_only" if level == "HIGH" else "sandbox", "reason": ""},
        "reasons": [],
    }


def test_decide_uses_assessment_level_when_provided(monkeypatch):
    monkeypatch.setattr(safety.sandbox, "is_available", lambda: True)
    # BinaryInfo has NO hints (would be LOW), but assessment says HIGH
    d = safety.decide(_info(), risk_assessment=_assess("HIGH", ["wiper_signature"]))
    assert d.risk_level == "HIGH"
    assert d.allowed is False
    assert d.mode == "static_only"


def test_decide_assessment_medium(monkeypatch):
    monkeypatch.setattr(safety.sandbox, "is_available", lambda: True)
    d = safety.decide(_info(), risk_assessment=_assess("MEDIUM", ["packer"]))
    assert d.risk_level == "MEDIUM"
    assert d.mode == "qiling_first"
    assert d.requires_confirmation is True


def test_decide_assessment_low(monkeypatch):
    monkeypatch.setattr(safety.sandbox, "is_available", lambda: True)
    d = safety.decide(_info(), risk_assessment=_assess("LOW", []))
    assert d.risk_level == "LOW"
    assert d.allowed is True
    assert d.mode == "sandbox"


def test_decide_falls_back_to_hints_when_no_assessment(monkeypatch):
    """Without a risk_assessment, the old hint-based path still works."""
    monkeypatch.setattr(safety.sandbox, "is_available", lambda: True)
    info = BinaryInfo(
        path="x", format="PE", arch="x86_64", bits=64, endian="little",
        entry=0x1000, sha256="a" * 64, size=1024, risk_hints=["kernel_driver"],
    )
    d = safety.decide(info)
    assert d.risk_level == "HIGH"
    assert d.allowed is False


def test_decide_docker_missing_overrides_assessment(monkeypatch):
    """Even with a LOW assessment, no sandbox => static-only."""
    monkeypatch.setattr(safety.sandbox, "is_available", lambda: False)
    d = safety.decide(_info(), risk_assessment=_assess("LOW", []))
    assert d.allowed is False
    assert d.mode == "static_only"
