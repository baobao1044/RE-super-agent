"""gdb backend (Linux) — process control + memory inspection via pygdbmi + gdb-mi.

Degrades to available=False when pygdbmi or gdb is unavailable.
"""
from __future__ import annotations

import importlib
import shutil


def _load_gdbmi():
    try:
        return importlib.import_module("pygdbmi")
    except Exception:  # noqa: BLE001
        return None


def _gdb_binary() -> str | None:
    return shutil.which("gdb")


# gdb-mi session registry (id -> gdbcontroller).
_sessions: dict = {}


def start(path: str, args: list[str] | None = None) -> dict:
    gdbmi = _load_gdbmi()
    if gdbmi is None or _gdb_binary() is None:
        return {"available": False, "error": "gdb/pygdbmi not installed"}
    try:
        controller = gdbmi.GdbController()
        controller.write(["-file-exec-and-symbols", path])
        controller.write(["-exec-arguments", *(args or [])])
        sid = str(id(controller))
        _sessions[sid] = controller
        return {"available": True, "session": sid}
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "error": str(exc)}


def set_breakpoint(session: str, location: str) -> dict:
    gdbmi = _load_gdbmi()
    if gdbmi is None:
        return {"available": False, "error": "gdb/pygdbmi not installed"}
    try:
        _sessions[session].write([f"-break-insert {location}"])
        return {"available": True, "breakpoint": location}
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "error": str(exc)}


def continue_exec(session: str) -> dict:
    gdbmi = _load_gdbmi()
    if gdbmi is None:
        return {"available": False, "error": "gdb/pygdbmi not installed"}
    try:
        _sessions[session].write(["-exec-continue"])
        return {"available": True, "running": True}
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "error": str(exc)}


def step(session: str) -> dict:
    gdbmi = _load_gdbmi()
    if gdbmi is None:
        return {"available": False, "error": "gdb/pygdbmi not installed"}
    try:
        _sessions[session].write(["-exec-step-instruction"])
        return {"available": True, "stepped": True}
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "error": str(exc)}


def read_memory(session: str, addr: int, size: int) -> dict:
    gdbmi = _load_gdbmi()
    if gdbmi is None:
        return {"available": False, "error": "gdb/pygdbmi not installed"}
    try:
        _sessions[session].write([f"-data-read-memory-bytes {addr} {size}"])
        return {"available": True, "addr": addr, "size": size}
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "error": str(exc)}


def get_regs(session: str) -> dict:
    gdbmi = _load_gdbmi()
    if gdbmi is None:
        return {"available": False, "error": "gdb/pygdbmi not installed"}
    try:
        _sessions[session].write(["-data-list-register-values", "x"])
        return {"available": True, "note": "registers via gdb-mi response"}
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "error": str(exc)}


def backtrace(session: str) -> dict:
    gdbmi = _load_gdbmi()
    if gdbmi is None:
        return {"available": False, "error": "gdb/pygdbmi not installed"}
    try:
        _sessions[session].write(["-stack-list-frames"])
        return {"available": True, "note": "frames via gdb-mi response"}
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "error": str(exc)}
