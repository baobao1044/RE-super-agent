"""WinDbg backend (Windows) — process control + memory inspection via pykd.

Degrades to available=False when pykd (WinDbg python engine) is unavailable.
"""
from __future__ import annotations

import importlib


def _load_pykd():
    try:
        return importlib.import_module("pykd")
    except Exception:  # noqa: BLE001
        return None


# pykd session registry (target -> process handle).
_sessions: dict = {}


def attach(target: str) -> dict:
    pykd = _load_pykd()
    if pykd is None:
        return {"available": False, "error": "pykd/WinDbg not installed"}
    try:
        pykd.startProcess(target)
        _sessions[target] = True
        return {"available": True, "session": target}
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "error": str(exc)}


def set_breakpoint(session: str, addr: int) -> dict:
    pykd = _load_pykd()
    if pykd is None:
        return {"available": False, "error": "pykd/WinDbg not installed"}
    try:
        pykd.setBp(addr)
        return {"available": True, "addr": addr}
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "error": str(exc)}


def continue_exec(session: str) -> dict:
    pykd = _load_pykd()
    if pykd is None:
        return {"available": False, "error": "pykd/WinDbg not installed"}
    try:
        pykd.go()
        return {"available": True, "running": True}
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "error": str(exc)}


def read_memory(session: str, addr: int, size: int) -> dict:
    pykd = _load_pykd()
    if pykd is None:
        return {"available": False, "error": "pykd/WinDbg not installed"}
    try:
        buf = pykd.loadBytes(addr, size)
        return {"available": True, "bytes": list(buf), "addr": addr, "size": size}
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "error": str(exc)}


def get_regs(session: str) -> dict:
    pykd = _load_pykd()
    if pykd is None:
        return {"available": False, "error": "pykd/WinDbg not installed"}
    try:
        regs = {r: pykd.reg(r) for r in ("rax", "rbx", "rcx", "rdx", "rsp", "rbp", "rip")}
        return {"available": True, "registers": regs}
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "error": str(exc)}
