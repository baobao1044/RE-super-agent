"""Planner — binary-type classification + playbook selection.

classify_binary_type maps (binary info + risk assessment + task) to one of the known
playbook types the workflow engine understands:
  crackme  - license-check / serial bypass, clean binary
  packed_vm - packer or VM-obfuscation hints (VMProtect/Themida/UPX/custom VM)
  malware  - HIGH risk or destructive/anti-VM-escape hints (static-only)
  ctf      - flag-extraction challenge

select_playbook returns the matching playbook name (used by the Supervisor as the
synthesis fallback when the LLM cannot design a valid DAG). The classification is a pure
heuristic so it runs without a cloud LLM.
"""
from __future__ import annotations

from tools.binary import BinaryInfo

# Hint -> playbook-type affinity. Packer/VM hints win over generic malware hints because a
# VM obfuscator is a stronger structural signal (it demands the deobfuscation specialist).
_PACKED_HINTS = {"packer", "obfuscated", "vmp0", "vmp1", "upx", "themida"}
_MALWARE_HINTS = {"ransomware_behavior", "wiper_signature", "kernel_driver",
                  "anti_vm_escape"}

KNOWN_TYPES = ("crackme", "packed_vm", "malware", "ctf")


def classify_binary_type(info: BinaryInfo, risk: dict | None = None,
                         *, task: str = "") -> str:
    """Return one of KNOWN_TYPES for this binary + task."""
    hints: set[str] = set()
    if risk is not None:
        hints.update(risk.get("risk_hints", []))
    hints.update(info.risk_hints)

    if hints & _PACKED_HINTS:
        return "packed_vm"
    risk_level = (risk or {}).get("risk_level", "")
    if risk_level == "HIGH" or (hints & _MALWARE_HINTS):
        return "malware"
    task_lower = (task or "").lower()
    if "flag" in task_lower or "ctf" in task_lower:
        return "ctf"
    return "crackme"


def select_playbook(info: BinaryInfo, risk: dict | None = None, *,
                    task: str = "") -> str:
    """Return the playbook name matching the classified binary type."""
    return classify_binary_type(info, risk, task=task)
