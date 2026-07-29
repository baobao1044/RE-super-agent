"""Tests for agent.core.playbooks — bundled template loader + directory seeding."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent.core import playbooks as pb  # noqa: E402
from agent.core.workflow import Workflow, WorkflowEngine  # noqa: E402


def test_list_bundled_returns_known_types():
    assert set(pb.list_bundled()) == {"crackme", "packed_vm", "malware", "ctf"}


def test_load_template_returns_valid_dag():
    d = pb.load_template("crackme")
    assert d["binary_type"] == "crackme"
    wf = Workflow.from_dict(d["workflow"])
    assert wf.validate() == []
    assert [n.id for n in wf.nodes] == ["n1", "n2", "n3", "n4", "n5"]


def test_load_template_unknown_raises():
    with pytest.raises(FileNotFoundError):
        pb.load_template("nope")


def test_seed_playbooks_dir_copies_templates(tmp_path):
    seeded = pb.seed_playbooks_dir(tmp_path)
    assert set(seeded) == set(pb.BUNDLED_PLAYBOOKS)
    for name in pb.BUNDLED_PLAYBOOKS:
        assert (tmp_path / f"{name}.json").exists()
    # re-seed without overwrite does not rewrite
    (tmp_path / "crackme.json").write_text('{"user": "custom"}')
    seeded2 = pb.seed_playbooks_dir(tmp_path)
    assert "crackme" not in seeded2  # not overwritten
    assert (tmp_path / "crackme.json").read_text() == '{"user": "custom"}'


def test_engine_can_load_seeded_playbook(tmp_path):
    # seed a fresh dir, then load each via WorkflowEngine.load_playbook
    pb.seed_playbooks_dir(tmp_path, overwrite=True)
    eng = WorkflowEngine(provider=None, sandbox=None, specialists={}, playbooks_dir=tmp_path)
    for name in pb.BUNDLED_PLAYBOOKS:
        wf = eng.load_playbook(name)
        assert wf.validate() == []
        assert all(n.status == "pending" for n in wf.nodes)
