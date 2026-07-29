"""Ghidra headless backend via pyghidra. Degrades to available=False when Ghidra/pyghidra
is not installed (the common case in minimal envs). The static MCP server routes
decompile_function/list_functions/xrefs through here and falls back to r2+capstone
when Ghidra is unavailable.
"""
from __future__ import annotations

import importlib
from pathlib import Path


def _load_pyghidra():
    try:
        return importlib.import_module("pyghidra")
    except Exception:  # noqa: BLE001
        return None


def _open_project(path):
    pyghidra = _load_pyghidra()
    if pyghidra is None:
        return None
    # pyghidra.open_program returns a GhidraProject handle.
    try:
        return pyghidra.open_program(str(path))
    except Exception:  # noqa: BLE001
        return None


def list_functions(path: str | Path) -> dict:
    proj = _open_project(path)
    if proj is None:
        return {"available": False, "error": "Ghidra/pyghidra not installed", "functions": []}
    try:
        listing = proj.program.getListing()
        fm = proj.program.getFunctionManager()
        funcs = []
        for f in fm.getFunctions(True):
            funcs.append({
                "addr": str(f.getEntryPoint()),
                "name": f.getName(),
                "size": f.getBody().getNumAddresses(),
            })
        proj.close()
        return {"available": True, "functions": funcs}
    except Exception as exc:  # noqa: BLE001
        proj.close()
        return {"available": False, "error": str(exc), "functions": []}


def decompile_function(path: str | Path, addr) -> dict:
    proj = _open_project(path)
    if proj is None:
        return {"available": False, "error": "Ghidra/pyghidra not installed", "decompilation": ""}
    try:
        from ghidra.app.decompiler import DecompInterface  # type: ignore
        program = proj.program
        fm = program.getFunctionManager()
        func = fm.getFunctionAt(program.getAddressFactory().getAddress(str(addr)))
        if func is None:
            proj.close()
            return {"available": True, "decompilation": "", "error": "no function at addr"}
        decomp = DecompInterface()
        decomp.openProgram(program)
        result = decomp.decompileFunction(func, 60, None)
        text = result.getDecompiledFunction().getC() if result.decompileCompleted() else ""
        decomp.dispose()
        proj.close()
        return {"available": True, "decompilation": text, "name": func.getName()}
    except Exception as exc:  # noqa: BLE001
        try:
            proj.close()
        except Exception:  # noqa: BLE001
            pass
        return {"available": False, "error": str(exc), "decompilation": ""}


def xrefs_to(path: str | Path, addr) -> dict:
    proj = _open_project(path)
    if proj is None:
        return {"available": False, "error": "Ghidra/pyghidra not installed", "xrefs": []}
    try:
        program = proj.program
        target = program.getAddressFactory().getAddress(str(addr))
        rm = program.getReferenceManager()
        refs = []
        for r in rm.getReferencesTo(target):
            refs.append({
                "from": str(r.getFromAddress()),
                "type": r.getReferenceType().getName(),
            })
        proj.close()
        return {"available": True, "xrefs": refs}
    except Exception as exc:  # noqa: BLE001
        proj.close()
        return {"available": False, "error": str(exc), "xrefs": []}
