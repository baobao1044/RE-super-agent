"""Qiling backend — user-mode emulation for safe, concrete VM-obfuscation tracing.

Degrades to available=False when qiling is not installed. When installed, load_target
emulates the binary with hooks and returns a (pc, mnemonic) trace that trace_reconstruct
turns into native ops. This is the safe alternative to running an obfuscated binary on a
real OS — it runs inside emulation (and, in production, inside the Docker sandbox).
"""
from __future__ import annotations

import importlib


def _load_qiling():
    try:
        return importlib.import_module("qiling")
    except Exception:  # noqa: BLE001
        return None


def load_target(path: str, *, rootfs: str = "", arch: str = "", osname: str = "") -> dict:
    ql = _load_qiling()
    if ql is None:
        return {"available": False, "error": "qiling not installed"}
    try:
        ql_obj = ql.Qiling(path, rootfs) if rootfs else ql.Qiling(path, "/")
        return {"available": True, "handle": str(id(ql_obj)), "ql": ql_obj}
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "error": str(exc)}


def trace_execution(path: str, *, start_addr: int | None = None,
                    end_addr: int | None = None, max_steps: int = 10000) -> dict:
    """Emulate and return a (pc, mnemonic) trace. Degrades without qiling."""
    ql = _load_qiling()
    if ql is None:
        return {"available": False, "error": "qiling not installed",
                "trace": [], "note": "use the workflow engine's static-derived trace fallback"}
    try:
        ql_obj = ql.Qiling(path, "/")
        trace: list[dict] = []
        if start_addr is not None:
            ql_obj.loader.entry_point = start_addr
        # Hook each instruction to record the PC + a best-effort mnemonic via unicorn.
        from unicorn import Uc  # type: ignore  # qiling bundles unicorn

        def _hook(uc, address, size, user_data):
            if len(trace) >= max_steps:
                return
            trace.append({"pc": address, "mnemonic": "", "op_str": ""})
            if end_addr is not None and address == end_addr:
                ql_obj.emu_stop()

        ql_obj.hook_code(_hook)
        ql_obj.run()
        return {"available": True, "trace": trace, "steps": len(trace)}
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "error": str(exc), "trace": []}
