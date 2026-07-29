"""RE workspace — the shared state specialists write to and the supervisor reads from.

Backed by a JSON file per session. Holds:
- binary meta (path/format/arch/bits/endian/sha256/size + risk_level/risk_hints)
- functions: discovered functions keyed by hex address
- findings: structured observations, each with an incrementing id
- hypotheses: guesses with status (open/confirmed/refuted)
- cross_refs: links across tools (static addr -> dynamic hook -> VM spec)
- vm_spec: deobfuscation's recovered VM model
- workflow_trace: append-only log of workflow actions + reasons (observability)
- checkpoints: immutable DAG snapshots for workflow resume / adaptation

Addresses are integers in the API but stored as hex strings so JSON round-trips cleanly.
"""
from __future__ import annotations

import copy
import json
import time
from pathlib import Path

from tools.binary import BinaryInfo


def _addr_key(addr: int) -> str:
    return hex(int(addr))


class Workspace:
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.binary: dict = {}
        self.functions: dict[str, dict] = {}   # hex-addr -> {addr, name, notes, source}
        self.findings: list[dict] = []
        self.hypotheses: list[dict] = []
        self.cross_refs: list[dict] = []
        self.vm_spec: dict | None = None
        self.workflow_trace: list[dict] = []
        self.checkpoints: dict[int, dict] = {}
        self._next_finding = 1
        self._next_hypo = 1
        self._next_checkpoint = 1

    # ------------------------------------------------------------------ binary
    def set_binary(self, info: BinaryInfo, risk_level: str, risk_hints: list[str] | None = None):
        self.binary = {
            "path": info.path,
            "format": info.format,
            "arch": info.arch,
            "bits": info.bits,
            "endian": info.endian,
            "entry": info.entry,
            "sha256": info.sha256,
            "size": info.size,
            "risk_level": risk_level,
            "risk_hints": list(risk_hints if risk_hints is not None else info.risk_hints),
        }

    # ---------------------------------------------------------------- functions
    def add_function(self, *, addr: int, name: str, notes: str = "", source: str = "static"):
        key = _addr_key(addr)
        if key in self.functions:
            # merge: update notes if provided
            if notes:
                self.functions[key]["notes"] = notes
            return self.functions[key]
        fn = {"addr": int(addr), "name": name, "notes": notes, "source": source}
        self.functions[key] = fn
        return fn

    def get_function(self, addr: int) -> dict | None:
        return self.functions.get(_addr_key(addr))

    # ----------------------------------------------------------------- findings
    def add_finding(self, *, kind: str, summary: str, detail: str = "",
                    source: str = "", confidence: float = 0.0) -> int:
        fid = self._next_finding
        self._next_finding += 1
        self.findings.append({
            "id": fid, "kind": kind, "summary": summary, "detail": detail,
            "source": source, "confidence": confidence,
        })
        return fid

    # ------------------------------------------------------------- hypotheses
    def add_hypothesis(self, text: str) -> int:
        hid = self._next_hypo
        self._next_hypo += 1
        self.hypotheses.append({"id": hid, "text": text, "status": "open", "evidence": ""})
        return hid

    def resolve_hypothesis(self, hid: int, *, status: str, evidence: str = ""):
        for h in self.hypotheses:
            if h["id"] == hid:
                h["status"] = status
                h["evidence"] = evidence
                return
        raise KeyError(f"no hypothesis {hid}")

    # -------------------------------------------------------------- cross-refs
    def add_cross_ref(self, *, static_addr: int, dynamic_hook: str | None = None,
                      vm_spec: dict | None = None, kind: str = "function", note: str = ""):
        self.cross_refs.append({
            "static_addr": int(static_addr),
            "dynamic_hook": dynamic_hook,
            "vm_spec": vm_spec,
            "kind": kind,
            "note": note,
        })

    def set_vm_spec(self, spec: dict):
        self.vm_spec = spec

    # -------------------------------------------------------- workflow trace
    def record_workflow_step(self, *, action: str, reason: str, extra: dict | None = None):
        step = {"action": action, "reason": reason, "ts": time.time()}
        if extra:
            step.update(extra)
        self.workflow_trace.append(step)

    def checkpoint(self) -> int:
        """Snapshot the current state (esp. workflow trace + functions) for resume.

        Returns the checkpoint version number.
        """
        ver = self._next_checkpoint
        self._next_checkpoint += 1
        self.checkpoints[ver] = {
            "version": ver,
            "workflow_trace": copy.deepcopy(self.workflow_trace),
            "functions": copy.deepcopy(self.functions),
            "findings": copy.deepcopy(self.findings),
        }
        return ver

    # --------------------------------------------------------- (de)serialise
    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "binary": self.binary,
            "functions": self.functions,
            "findings": self.findings,
            "hypotheses": self.hypotheses,
            "cross_refs": self.cross_refs,
            "vm_spec": self.vm_spec,
            "workflow_trace": self.workflow_trace,
            "checkpoints": self.checkpoints,
            "_next_finding": self._next_finding,
            "_next_hypo": self._next_hypo,
            "_next_checkpoint": self._next_checkpoint,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Workspace":
        ws = cls(d["session_id"])
        ws.binary = d.get("binary", {})
        ws.functions = d.get("functions", {})
        ws.findings = d.get("findings", [])
        ws.hypotheses = d.get("hypotheses", [])
        ws.cross_refs = d.get("cross_refs", [])
        ws.vm_spec = d.get("vm_spec")
        ws.workflow_trace = d.get("workflow_trace", [])
        ws.checkpoints = {int(k): v for k, v in d.get("checkpoints", {}).items()}
        ws._next_finding = d.get("_next_finding", len(ws.findings) + 1)
        ws._next_hypo = d.get("_next_hypo", len(ws.hypotheses) + 1)
        ws._next_checkpoint = d.get("_next_checkpoint", len(ws.checkpoints) + 1)
        return ws

    def save(self, path: str | Path):
        Path(path).write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "Workspace":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))
