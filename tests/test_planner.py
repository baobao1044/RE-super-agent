"""Tests for agent.core.planner — binary-type classification + playbook selection.

Stage 9b: classify_binary_type maps (binary info + risk assessment + task) to one of the
known playbook types (crackme / packed_vm / malware / ctf) using risk hints + task
keywords. select_playbook returns the matching playbook name and is used by the Supervisor
as the synthesis fallback.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent.core.planner import classify_binary_type, select_playbook  # noqa: E402


def _info(risk_hints=None):
    from tools.binary import BinaryInfo
    return BinaryInfo(path="x", format="PE", arch="x86_64", bits=64, endian="little",
                      entry=0x401000, sha256="abc", size=100,
                      risk_hints=risk_hints or [])


def _risk(level="LOW", hints=None):
    return {"risk_level": level, "risk_hints": hints or []}


def test_classify_packed_vm_on_packer_or_vm_hints():
    assert classify_binary_type(_info(), _risk(hints=["packer"])) == "packed_vm"
    assert classify_binary_type(_info(), _risk(hints=["obfuscated"])) == "packed_vm"
    assert classify_binary_type(_info(), _risk(hints=["vmp0"])) == "packed_vm"


def test_classify_malware_on_high_risk_or_malware_hints():
    assert classify_binary_type(_info(), _risk(level="HIGH")) == "malware"
    assert classify_binary_type(_info(), _risk(hints=["ransomware_behavior"])) == "malware"
    assert classify_binary_type(_info(), _risk(hints=["kernel_driver"])) == "malware"
    assert classify_binary_type(_info(), _risk(hints=["wiper_signature"])) == "malware"


def test_classify_ctf_on_task_keywords():
    assert classify_binary_type(_info(), _risk(), task="extract the flag") == "ctf"
    assert classify_binary_type(_info(), _risk(), task="solve CTF challenge") == "ctf"


def test_classify_crackme_default():
    assert classify_binary_type(_info(), _risk(), task="bypass license check") == "crackme"
    assert classify_binary_type(_info(), _risk()) == "crackme"


def test_classify_packed_vm_takes_precedence_over_malware_hints():
    # packer hint is a stronger signal of a VM obfuscator than a generic malware hint
    assert classify_binary_type(_info(), _risk(hints=["packer", "anti_debug"])) == "packed_vm"


def test_select_playbook_returns_known_name():
    assert select_playbook(_info(), _risk(hints=["packer"]), task="devirtualize") == "packed_vm"
    assert select_playbook(_info(), _risk(level="HIGH"), task="analyze") == "malware"
    assert select_playbook(_info(), _risk(), task="get the flag") == "ctf"
    assert select_playbook(_info(), _risk(), task="bypass") == "crackme"
