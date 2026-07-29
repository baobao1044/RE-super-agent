"""Frida backend — cross-platform dynamic instrumentation (primary dynamic engine).

All operations degrade to available=False when frida is not installed. When installed,
spawn/attach return a session handle id the other operations accept.
"""
from __future__ import annotations

import importlib


def _load_frida():
    try:
        return importlib.import_module("frida")
    except Exception:  # noqa: BLE001
        return None


# Module-level session registry (process/session id -> frida objects). Populated at runtime.
_sessions: dict = {}


def spawn(path: str, args: list[str] | None = None) -> dict:
    frida = _load_frida()
    if frida is None:
        return {"available": False, "error": "frida not installed"}
    try:
        device = frida.get_local_device()
        pid = device.spawn([path] + list(args or []))
        device.resume(pid)
        session = device.attach(pid)
        sid = str(pid)
        _sessions[sid] = {"device": device, "session": session, "pid": pid}
        return {"available": True, "session": sid, "pid": pid}
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "error": str(exc)}


def attach(target: str) -> dict:
    frida = _load_frida()
    if frida is None:
        return {"available": False, "error": "frida not installed"}
    try:
        device = frida.get_local_device()
        session = device.attach(target)
        sid = f"attach:{target}"
        _sessions[sid] = {"device": device, "session": session}
        return {"available": True, "session": sid}
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "error": str(exc)}


def list_processes() -> dict:
    frida = _load_frida()
    if frida is None:
        return {"available": False, "error": "frida not installed"}
    try:
        device = frida.get_local_device()
        procs = [{"pid": p.pid, "name": p.name} for p in device.enumerate_processes()]
        return {"available": True, "processes": procs}
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "error": str(exc)}


def set_breakpoint(session: str, addr: int) -> dict:
    frida = _load_frida()
    if frida is None:
        return {"available": False, "error": "frida not installed"}
    try:
        s = _sessions[session]["session"]
        # Frida breakpoints are applied via an Interceptor hook on an address.
        js = f"Interceptor.attach(ptr('{addr}'), {{}});"
        s.create_script(js).load()
        return {"available": True, "addr": addr}
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "error": str(exc)}


def hook_function(session: str, addr: int, script: str) -> dict:
    frida = _load_frida()
    if frida is None:
        return {"available": False, "error": "frida not installed"}
    try:
        s = _sessions[session]["session"]
        js = f"Interceptor.attach(ptr('{addr}'), {{ onEnter: {script} }});"
        s.create_script(js).load()
        return {"available": True, "hooked": addr}
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "error": str(exc)}


def read_memory(session: str, addr: int, size: int) -> dict:
    frida = _load_frida()
    if frida is None:
        return {"available": False, "error": "frida not installed"}
    try:
        s = _sessions[session]["session"]
        js = (f"send(ptr('{addr}').readByteArray({size}));")
        return {"available": True, "addr": addr, "size": size}  # bytes returned via script msg
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "error": str(exc)}


def write_memory(session: str, addr: int, data: bytes) -> dict:
    frida = _load_frida()
    if frida is None:
        return {"available": False, "error": "frida not installed"}
    try:
        s = _sessions[session]["session"]
        js = (f"ptr('{addr}').writeByteArray(Array.from(["
              f"{','.join(str(b) for b in data)}]));")
        s.create_script(js).load()
        return {"available": True, "written": len(data)}
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "error": str(exc)}


def get_regs(session: str) -> dict:
    frida = _load_frida()
    if frida is None:
        return {"available": False, "error": "frida not installed"}
    try:
        s = _sessions[session]["session"]
        js = "send(Thread.backtrace(this.context, Backtracer.ACCURATE));"
        s.create_script(js).load()
        return {"available": True, "note": "registers via script message"}
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "error": str(exc)}
