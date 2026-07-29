"""Tests for tools/sandbox.py — Docker sandbox spawn, isolation config, code-gen runner,
and the Docker-unavailable fallback (must NEVER execute on host).

Docker itself is NOT required for these tests: we inject a fake client that records the
arguments it was called with, so we assert the *hardening flags* are correct without
needing a running daemon.
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

import tools.sandbox as sandbox  # noqa: E402


# ---------------------------------------------------------------------------
# Fake docker client: records the last run() call and lets tests assert on it.
# ---------------------------------------------------------------------------
class FakeContainer:
    def __init__(self, stdout=b'{"ok": true, "result": {"flag": "CTF{x}"}}', exit_code=0):
        self._stdout = stdout
        self._exit = exit_code

    def wait(self):
        return {"StatusCode": self._exit}

    def logs(self, stream=False, **_):
        if stream:
            return iter([self._stdout])
        return self._stdout


class FakeDockerClient:
    """A minimal stand-in for docker.from_env().

    Records the run() kwargs so tests can assert hardening. Returns a FakeContainer.
    """

    def __init__(self, container=None):
        self.container = container or FakeContainer()
        self.last_image = None
        self.last_command = None
        self.last_kwargs = None

    def run(self, image, command, **kwargs):
        self.last_image = image
        self.last_command = command
        self.last_kwargs = kwargs
        return self.container


# ---------------------------------------------------------------------------
# is_available / get_client
# ---------------------------------------------------------------------------
def test_is_available_false_when_docker_sdk_missing(monkeypatch):
    """If the docker SDK import fails, is_available() returns False (no host exec)."""
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "docker":
            raise ImportError("no docker sdk")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    # reset cached availability
    monkeypatch.setattr(sandbox, "_available_cache", None)
    assert sandbox.is_available() is False


def test_get_client_returns_injected(monkeypatch):
    fake = FakeDockerClient()
    monkeypatch.setattr(sandbox, "_available_cache", True)
    monkeypatch.setattr(sandbox, "_get_raw_client", lambda: fake)
    c = sandbox.get_client()
    assert c is fake


# ---------------------------------------------------------------------------
# run_codegen: hardening flags applied + result parsed
# ---------------------------------------------------------------------------
def test_run_codegen_applies_hardening(monkeypatch, tmp_path):
    fake = FakeDockerClient()
    monkeypatch.setattr(sandbox, "_available_cache", True)
    monkeypatch.setattr(sandbox, "_get_raw_client", lambda: fake)

    script = tmp_path / "snippet.py"
    script.write_text("import json; print(json.dumps({'flag':'CTF{x}'}))")

    result = sandbox.run_codegen(script_path=script, image="re-agent:full", timeout=30)
    # hardening kwargs present
    kw = fake.last_kwargs
    assert kw.get("network_disabled") is True or kw.get("network") == "none"
    assert kw.get("read_only") is True
    assert "ALL" in kw.get("cap_drop", [])
    assert kw.get("pids_limit") is not None or "pids_limit" in kw
    # result parsed from container stdout
    assert result["ok"] is True
    assert result["result"] == {"flag": "CTF{x}"}


def test_run_codegen_command_mounts_script_and_input(monkeypatch, tmp_path):
    fake = FakeDockerClient()
    monkeypatch.setattr(sandbox, "_available_cache", True)
    monkeypatch.setattr(sandbox, "_get_raw_client", lambda: fake)

    script = tmp_path / "s.py"
    script.write_text("print('hi')")
    injson = tmp_path / "in.json"
    injson.write_text('{"q": 1}')

    sandbox.run_codegen(script_path=script, input_path=injson, image="re-agent:full", timeout=30)
    cmd = fake.last_command
    # command runs the codegen runner with the script (and input if given)
    assert any("codegen_runner.py" in str(part) for part in cmd)
    assert any(str(script) in str(part) or "/scratch" in str(part) for part in cmd)
    # script + input must be bind-mounted (volumes), not copied
    vols = fake.last_kwargs.get("volumes", {})
    assert any("s.py" in str(k) or str(script) in str(k) for k in vols)


def test_run_codegen_nonzero_exit_marks_failed(monkeypatch, tmp_path):
    container = FakeContainer(stdout=b'{"ok": true, "result": null}', exit_code=1)
    fake = FakeDockerClient(container=container)
    monkeypatch.setattr(sandbox, "_available_cache", True)
    monkeypatch.setattr(sandbox, "_get_raw_client", lambda: fake)

    script = tmp_path / "s.py"
    script.write_text("import sys; sys.exit(1)")
    result = sandbox.run_codegen(script_path=script, image="re-agent:full", timeout=30)
    assert result["ok"] is False
    assert "exit_code" in result and result["exit_code"] == 1


# ---------------------------------------------------------------------------
# Fallback: Docker unavailable -> refuse to execute, raise (never run on host)
# ---------------------------------------------------------------------------
def test_run_codegen_refuses_when_docker_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(sandbox, "_available_cache", False)
    script = tmp_path / "s.py"
    script.write_text("print('would run on host - forbidden')")
    with pytest.raises(sandbox.SandboxUnavailableError):
        sandbox.run_codegen(script_path=script, image="re-agent:full", timeout=30)


def test_environment_for_risk_low(monkeypatch):
    monkeypatch.setattr(sandbox, "_available_cache", True)
    env = sandbox.environment_for_risk("LOW", require_full=False)
    assert env == "re-agent:core"


def test_environment_for_risk_medium_prefers_full(monkeypatch):
    monkeypatch.setattr(sandbox, "_available_cache", True)
    env = sandbox.environment_for_risk("MEDIUM", require_full=True)
    assert env == "re-agent:full"


def test_environment_for_risk_high_returns_none(monkeypatch):
    """HIGH risk must never return an execution environment."""
    monkeypatch.setattr(sandbox, "_available_cache", True)
    assert sandbox.environment_for_risk("HIGH") is None
