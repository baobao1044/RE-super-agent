"""Safety / risk gate — decides HOW (or whether) a binary may be executed.

This is the cross-cutting safety concern for the whole agent: before any dynamic
execution or AI code-gen, the supervisor calls decide(binary_info) and gets back an
ExecutionDecision describing the permitted mode. HIGH-risk binaries are never executed;
without a Docker sandbox, EVERYTHING degrades to static-only (never host execution).

Risk levels: LOW / MEDIUM / HIGH.

The classify step is heuristic (cheap, from risk_hints). The real heavy risk scan
(capa/YARA + behavioral) is provided by the malware MCP server in Stage 3, which feeds
richer hints back here via the workspace. For Stage 1 we implement the gate itself and
the decision logic; the hints list is populated by binary.py + (later) risk_scan.

Modes:
  - sandbox       -> run inside the Docker sandbox image (LOW)
  - qiling_first  -> emulate in Qiling inside Docker first; real exec needs confirm (MEDIUM)
  - static_only   -> no execution at all (HIGH, or sandbox unavailable)
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from tools import sandbox
from tools.binary import BinaryInfo

log = logging.getLogger(__name__)

# Hints that immediately push a binary to HIGH (refuse dynamic execution entirely).
HIGH_HINTS = {
    "wiper_signature",
    "kernel_driver",
    "anti_vm_escape",
    "ransomware_behavior",
    "bootkit",
    "rootkit",
}
# Hints that raise suspicion to MEDIUM (sandbox + confirmation for real exec).
MEDIUM_HINTS = {
    "is_dll",
    "anti_debug",
    "anti_vm",
    "packer",
    "obfuscated",
    "unusual_imports",
}


@dataclass
class ExecutionDecision:
    """The safety layer's verdict on a binary."""

    allowed: bool           # may any execution happen at all?
    mode: str               # "sandbox" | "qiling_first" | "static_only"
    risk_level: str          # "LOW" | "MEDIUM" | "HIGH"
    requires_confirmation: bool  # must a human approve before real execution?
    reason: str = ""


def classify_risk(info: BinaryInfo) -> str:
    """Map a binary's risk_hints to LOW / MEDIUM / HIGH. HIGH dominates."""
    hints = set(info.risk_hints or [])
    if hints & HIGH_HINTS:
        return "HIGH"
    if hints & MEDIUM_HINTS:
        return "MEDIUM"
    return "LOW"


def decide(info: BinaryInfo) -> ExecutionDecision:
    """Decide how a binary may be (or must not be) executed."""
    risk = classify_risk(info)

    # No sandbox => never execute, regardless of risk. Static analysis only.
    if not sandbox.is_available():
        return ExecutionDecision(
            allowed=False,
            mode="static_only",
            risk_level=risk,
            requires_confirmation=False,
            reason="Docker sandbox unavailable; execution forbidden (static-only fallback)",
        )

    if risk == "HIGH":
        return ExecutionDecision(
            allowed=False,
            mode="static_only",
            risk_level="HIGH",
            requires_confirmation=False,
            reason="HIGH risk (hostile/catastrophic signature); dynamic execution refused",
        )
    if risk == "MEDIUM":
        return ExecutionDecision(
            allowed=True,
            mode="qiling_first",
            risk_level="MEDIUM",
            requires_confirmation=True,
            reason="MEDIUM risk: emulate in Qiling-in-Docker first; real execution needs confirmation",
        )
    # LOW
    return ExecutionDecision(
        allowed=True,
        mode="sandbox",
        risk_level="LOW",
        requires_confirmation=False,
        reason="LOW risk: execution permitted inside the Docker sandbox",
    )
