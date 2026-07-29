"""Tests for agent.cli — the re-agent command-line entry point.

Stage 9c: the CLI parses args (one-shot: `re-agent <binary> "<task>"`; with --trace it
prints the workflow trace). `main` builds a Supervisor from config + the real specialists
and prints a formatted report. Tests inject a fake supervisor-builder so no cloud LLM /
Docker is needed; they cover arg parsing, report formatting, and the trace view.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent import cli  # noqa: E402


def test_parse_args_one_shot():
    a = cli.parse_args(["x.exe", "bypass license check"])
    assert a.binary == "x.exe"
    assert a.task == "bypass license check"
    assert a.trace is False
    assert a.json is False


def test_parse_args_trace_and_json_flags():
    a = cli.parse_args(["x.exe", "do something", "--trace", "--json"])
    assert a.trace is True
    assert a.json is True


def test_format_report_includes_summary_and_binary(tmp_path):
    report = {
        "task": "t",
        "binary": {"path": "x.exe", "format": "PE", "arch": "x86_64", "risk_level": "LOW"},
        "risk_level": "LOW",
        "summary": "Analyzed x.exe (PE/x86_64, risk LOW); workflow 3/3 nodes done.",
        "findings": [{"id": 1, "kind": "risk_level", "summary": "Risk LOW", "source": "malware"}],
        "hypotheses": [], "functions": [], "vm_spec": None,
        "workflow": {"nodes": [{"id": "n1", "status": "done"}], "edges": []},
        "workflow_trace": [],
    }
    out = cli.format_report(report)
    assert "x.exe" in out
    assert "LOW" in out
    assert "workflow" in out.lower()
    assert "findings" in out.lower()


def test_format_trace_lists_steps():
    report = {
        "workflow_trace": [
            {"action": "execute_node", "reason": "scan", "node": "n1",
             "specialist": "malware", "status": "done"},
            {"action": "adapt", "reason": "VM detected", "anomaly": "vm_detected",
             "node": "n2", "patch_action": "insert_after"},
        ],
    }
    out = cli.format_trace(report["workflow_trace"])
    assert "n1" in out
    assert "scan" in out
    assert "adapt" in out.lower()
    assert "VM detected" in out


def test_main_one_shot_prints_report(monkeypatch, capsys, tmp_path):
    p = tmp_path / "x.elf"
    p.write_bytes(b"\x7fELF" + b"\x00" * 60)
    fake_report = {
        "task": "find flag", "binary": {"path": str(p), "format": "ELF", "arch": "x86_64",
                                          "risk_level": "LOW"},
        "risk_level": "LOW",
        "summary": "Analyzed; done.", "findings": [], "hypotheses": [],
        "functions": [], "vm_spec": None,
        "workflow": {"nodes": [{"id": "n1", "status": "done"}], "edges": []},
        "workflow_trace": [],
    }
    class FakeSupervisor:
        def __init__(self, **kw): pass
        def run(self, *, binary_path, task): return dict(fake_report)
    monkeypatch.setattr(cli, "build_supervisor", lambda **kw: FakeSupervisor())
    rc = cli.main([str(p), "find flag"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "done" in out.lower() or "analyzed" in out.lower()


def test_main_trace_flag_prints_trace(monkeypatch, capsys, tmp_path):
    p = tmp_path / "x.elf"
    p.write_bytes(b"\x7fELF" + b"\x00" * 60)
    fake_report = {
        "task": "t", "binary": {"path": str(p), "format": "ELF", "arch": "x86_64",
                                 "risk_level": "LOW"},
        "risk_level": "LOW", "summary": "done", "findings": [], "hypotheses": [],
        "functions": [], "vm_spec": None,
        "workflow": {"nodes": [], "edges": []},
        "workflow_trace": [{"action": "execute_node", "reason": "scan", "node": "n1",
                             "specialist": "malware", "status": "done"}],
    }
    class FakeSupervisor:
        def __init__(self, **kw): pass
        def run(self, *, binary_path, task): return dict(fake_report)
    monkeypatch.setattr(cli, "build_supervisor", lambda **kw: FakeSupervisor())
    rc = cli.main([str(p), "do thing", "--trace"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "trace" in out.lower() or "n1" in out


def test_main_missing_binary_errors(monkeypatch, capsys):
    rc = cli.main(["nonexistent.bin", "task"])
    assert rc != 0
    err = capsys.readouterr().err
    assert "not found" in err.lower() or "error" in err.lower()
