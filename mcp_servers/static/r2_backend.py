"""radare2/rizin backend via r2pipe, with a capstone fallback for raw disassembly.

r2 gives fast function listing / xrefs / strings when installed. When r2 (or r2pipe) is
absent, list_functions/xrefs degrade to available=False, BUT disassembly falls back to
capstone (always installed) so the static specialist can still read bytes. Strings fall
back to the malware strings_backend.
"""
from __future__ import annotations

import importlib
from pathlib import Path

from tools.binary import analyze


def _load_r2pipe():
    try:
        return importlib.import_module("r2pipe")
    except Exception:  # noqa: BLE001
        return None


def _open_r2(path):
    r2pipe = _load_r2pipe()
    if r2pipe is None:
        return None
    try:
        return r2pipe.open(str(path))
    except Exception:  # noqa: BLE001 — r2 binary missing
        return None


# ---------------------------------------------------------------------------
def list_functions(path: str | Path) -> dict:
    r2 = _open_r2(path)
    if r2 is None:
        return {"available": False, "error": "radare2/rizin not installed", "functions": []}
    try:
        raw = r2.cmd("aflj")  # analyze + list functions as JSON
        r2.quit()
        funcs = []
        if raw and raw.strip():
            import json
            for f in json.loads(raw):
                funcs.append({
                    "addr": f.get("offset", f.get("addr")),
                    "name": f.get("name", ""),
                    "size": f.get("size", 0),
                })
        return {"available": True, "functions": funcs}
    except Exception as exc:  # noqa: BLE001
        r2.quit()
        return {"available": False, "error": str(exc), "functions": []}


def xrefs_to(path: str | Path, addr) -> dict:
    r2 = _open_r2(path)
    if r2 is None:
        return {"available": False, "error": "radare2/rizin not installed", "xrefs": []}
    try:
        r2.cmd(f"s {addr}")
        raw = r2.cmd("axtj")
        r2.quit()
        import json
        refs = json.loads(raw) if raw and raw.strip() else []
        return {"available": True,
                "xrefs": [{"addr": r.get("from"), "type": r.get("type", "")} for r in refs]}
    except Exception as exc:  # noqa: BLE001
        r2.quit()
        return {"available": False, "error": str(exc), "xrefs": []}


def disassemble(path: str | Path, *, addr: int = 0, count: int = 64,
                arch: str = "x86_64", bits: int = 64, file_offset: int = 0) -> dict:
    """Disassemble raw bytes via capstone (r2-independent fallback, always available).

    `addr` is the *virtual address* reported with each instruction (what RE tools care
    about). `file_offset` is the byte offset into the file where the code starts; for a
    raw blob you pass the same value as `addr`, but for a real binary they differ.
    """
    try:
        from capstone import Cs, CS_ARCH_X86, CS_ARCH_ARM64, CS_ARCH_ARM, CS_MODE_64, CS_MODE_32, CS_MODE_ARM
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "error": f"capstone missing: {exc}", "instructions": []}

    data = Path(path).read_bytes()
    offset = file_offset if file_offset < len(data) else 0
    code = data[offset:offset + count * 16]

    md = None
    a = arch.lower()
    try:
        if a in ("x86_64", "amd64"):
            md = Cs(CS_ARCH_X86, CS_MODE_64)
        elif a == "x86":
            md = Cs(CS_ARCH_X86, CS_MODE_32)
        elif a == "aarch64":
            md = Cs(CS_ARCH_ARM64, CS_MODE_ARM if bits == 32 else CS_MODE_ARM)
        elif a == "arm":
            md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    except Exception:  # noqa: BLE001
        md = None

    if md is None:
        return {"available": True, "instructions": [], "arch": arch}

    md.detail = False
    instructions = []
    # `addr` is the virtual address reported; capstone advances from it.
    for ins in md.disasm(code, addr):
        instructions.append({
            "addr": ins.address,
            "mnemonic": ins.mnemonic,
            "op_str": ins.op_str,
            "bytes": ins.bytes.hex(),
        })
    return {"available": True, "instructions": instructions, "arch": arch}


def strings(path: str | Path, min_len: int = 4) -> dict:
    """Strings: try r2 izz, else fall back to the pure strings_backend."""
    from mcp_servers.malware import strings_backend
    r2 = _open_r2(path)
    if r2 is None:
        return strings_backend.extract_strings_entropy(path, min_len=min_len)
    try:
        raw = r2.cmd(f"izzj~[{min_len}]")
        r2.quit()
        import json
        out = []
        if raw and raw.strip():
            for s in json.loads(raw):
                out.append(s.get("string", ""))
        return {"strings": out, "string_count": len(out),
                "entropy": strings_backend.extract_strings_entropy(path, min_len=min_len)["entropy"]}
    except Exception:  # noqa: BLE001
        r2.quit()
        return strings_backend.extract_strings_entropy(path, min_len=min_len)


def get_info(path: str | Path) -> dict:
    """Return detected binary metadata via tools.binary.analyze."""
    return analyze(path).__dict__ if hasattr(analyze(path), "__dict__") else {}
