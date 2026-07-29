"""Anti-analysis detection — pure-static pattern scan for anti-debug / anti-VM / TLS-callback
indicators. Runs WITHOUT any dynamic engine. The dynamic specialist calls this BEFORE
spawning/attaching a process so it can patch / hide / emulate as needed.

`detect(path)` returns the categories of indicators found + aggregated hints that feed the
safety gate. `recommend_handling(hints)` maps those hints to concrete handling steps.
"""
from __future__ import annotations

from pathlib import Path

# API/strings indicating anti-debugging techniques.
ANTI_DEBUG_MARKERS = [
    b"IsDebuggerPresent",
    b"CheckRemoteDebuggerPresent",
    b"OutputDebugStringA",
    b"OutputDebugStringW",
    b"NtSetInformationThread",
    b"BeingDebugged",
    b"NtQueryInformationProcess",
    b"ProcessDebugFlags",
    b"ProcessDebugPort",
    b"DebugActiveProcess",
    b"DbgBreakPoint",
    b"DbgUiRemoteBreakin",
]

ANTI_VM_MARKERS = [
    b"VMware",
    b"VirtualBox",
    b"VBoxService",
    b"\\VBoxGuest",
    b"VBoxGuest",
    b"QEMU",
    b"Xen",
    b"HYPERV",
    b"Hyper-V",
    b"cpuid",
    b"rdtsc",
]

# Section names / patterns suggesting TLS callbacks / entry-point traps.
TLS_INDICATORS = [b".tls", b"_tls_", b"TLS_Callback"]


def _find_all(data: bytes, markers: list[bytes]) -> list[str]:
    found = []
    for m in markers:
        if m in data:
            found.append(m.decode("utf-8", errors="replace"))
    return found


def detect(path: str | Path) -> dict:
    """Scan a binary for anti-analysis indicators (pure static)."""
    data = Path(path).read_bytes()
    ad = _find_all(data, ANTI_DEBUG_MARKERS)
    avm = _find_all(data, ANTI_VM_MARKERS)
    tls = _find_all(data, TLS_INDICATORS)

    hints: list[str] = []
    if ad:
        hints.append("anti_debug")
    if avm:
        hints.append("anti_vm")
    if tls:
        hints.append("tls_callback")

    return {
        "anti_debug": ad,
        "anti_vm": avm,
        "tls_callback": tls,
        "hints": hints,
    }


def recommend_handling(anti_hints: list[str]) -> dict:
    """Map detected anti-analysis hints to handling steps the dynamic specialist should apply.

    - anti_debug -> patch the checks + hide the debugger (ScyllaHide-style).
    - anti_vm    -> emulate a clean environment (fake host strings/keys).
    - tls_callback -> set breakpoints at TLS callbacks before the real entry point.
    """
    hints = set(anti_hints or [])
    return {
        "patch_anti_debug": "anti_debug" in hints,
        "hide_debugger": "anti_debug" in hints,
        "emulate_clean_environment": "anti_vm" in hints,
        "break_at_tls_callbacks": "tls_callback" in hints,
    }
