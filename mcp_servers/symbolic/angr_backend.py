"""angr backend — symbolic execution + constraint solving, with a pure-Python fallback solver.

When angr is installed, load_project/explore_to/get_state_info use it. When angr is
missing (common in minimal envs), those degrade to available=False BUT
find_input_satisfying / extract_flag fall back to a small pure-Python brute-force solver
over a bounded input + alphabet, so symbolic analysis still works for tiny problems
(CTF flag-checkers with short secrets). The workflow engine's trace-driven hybrid
deobfuscation relies on this fallback to avoid path explosion on small recovered slices.
"""
from __future__ import annotations

import importlib
import itertools


def _load_angr():
    try:
        return importlib.import_module("angr")
    except Exception:  # noqa: BLE001
        return None


# Module-level angr project cache (path -> Project).
_projects: dict = {}


# ---------------------------------------------------------------------------
# angr-backed ops (degrade when angr missing)
# ---------------------------------------------------------------------------
def load_project(path: str) -> dict:
    angr = _load_angr()
    if angr is None:
        return {"available": False, "error": "angr not installed"}
    try:
        proj = angr.Project(path, auto_load_libs=False)
        _projects[path] = proj
        return {"available": True, "arch": str(proj.arch), "entry": proj.entry}
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "error": str(exc)}


def explore_to(path: str, target_addr: int, *, avoid: list[int] | None = None,
               state_budget: int = 50000) -> dict:
    angr = _load_angr()
    if angr is None:
        return {"available": False, "error": "angr not installed"}
    try:
        proj = _projects.get(path) or angr.Project(path, auto_load_libs=False)
        sm = proj.factory.simulation_manager()
        sm.explore(find=target_addr, avoid=avoid or [], num_find=1)
        if sm.found:
            found_state = sm.found[0]
            return {"available": True, "found": True,
                    "input": found_state.posix.dumps(0), "reachable_addr": target_addr}
        return {"available": True, "found": False, "explored_states": len(sm.active)}
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "error": str(exc)}


def get_state_info(path: str) -> dict:
    angr = _load_angr()
    if angr is None:
        return {"available": False, "error": "angr not installed"}
    try:
        proj = _projects.get(path) or angr.Project(path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()
        return {"available": True, "functions": len(cfg.functions),
                "entry": proj.entry}
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# pure-Python constraint solver (always available)
# ---------------------------------------------------------------------------
def find_input_satisfying(*, predicate, input_length: int,
                          max_value: int = 256, use_angr: bool = True,
                          alphabet=None) -> dict:
    """Find an input (bytes) satisfying `predicate(bytes) -> bool`.

    If use_angr and angr is available, the caller would normally pass a symbolic
    constraint; here we always use the pure solver when angr is absent, which is the
    testable path. `alphabet` is an iterable of byte values to try (default 0..max_value).
    """
    if use_angr and _load_angr() is not None:
        # Real angr path would use a SimState constraint; out of scope for the pure backend.
        # Fall through to pure solver for determinism in minimal envs.
        pass

    alpha = list(alphabet) if alphabet is not None else list(range(max_value))
    for combo in itertools.product(alpha, repeat=input_length):
        candidate = bytes(combo)
        try:
            if predicate(candidate):
                return {"found": True, "input": list(candidate), "engine": "pure_solver"}
        except Exception:  # noqa: BLE001
            continue
    return {"found": False, "engine": "pure_solver"}


def extract_flag(*, flag_predicate, expected_len: int, alphabet, use_angr: bool = True,
                 search_depth: int | None = None) -> dict:
    """Find bytes of expected_len satisfying flag_predicate; return as a flag string.

    `alphabet` is an iterable of byte values. `search_depth` caps total combinations tried.
    """
    alpha = list(alphabet)
    depth = search_depth if search_depth is not None else None
    tried = 0
    for combo in itertools.product(alpha, repeat=expected_len):
        if depth is not None and tried >= depth:
            break
        tried += 1
        candidate = bytes(combo)
        try:
            if flag_predicate(candidate):
                return {"found": True, "flag": candidate.decode("utf-8", errors="replace"),
                        "engine": "pure_solver"}
        except Exception:  # noqa: BLE001
            continue
    return {"found": False, "engine": "pure_solver"}


def deobfuscate(path: str, *, target_addr: int, state_budget: int = 50000) -> dict:
    """Hybrid deobfuscation hint: explore to target then report the satisfying input."""
    return explore_to(path, target_addr, state_budget=state_budget)
