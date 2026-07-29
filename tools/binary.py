"""Binary metadata detection.

Parses just enough of a binary's headers to identify format (ELF/PE), architecture,
bit-width, endianness, entry point, and a couple of cheap risk hints. The heavy lifting
(decompilation, CFG, imports) lives in the MCP backends; this module is the cheap,
dependency-light first step that every specialist shares.

Core detection uses raw header bytes (no third-party deps required). pefile is used for
PE when available (cleaner optional-header access) and degrades to a manual parse.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from pathlib import Path

# --- machine -> arch name maps ------------------------------------------------
ELF_MACHINE_ARCH = {
    3: "x86",
    62: "x86_64",
    40: "arm",
    183: "aarch64",
}
PE_MACHINE_ARCH = {
    0x014C: "x86",
    0x8664: "x86_64",
    0x01C0: "arm",
    0xAA64: "aarch64",
}

IMAGE_FILE_DLL = 0x2000


@dataclass
class BinaryInfo:
    """Cheap metadata about a binary, detected from its headers."""

    path: str
    format: str            # "ELF" | "PE" | "unknown"
    arch: str              # "x86" | "x86_64" | "arm" | "aarch64" | "unknown" | "elf_<n>" | "pe_<hex>"
    bits: int | None       # 32 | 64 | None
    endian: str | None     # "little" | "big" | None
    entry: int | None       # raw entry point (file/va as parsed)
    sha256: str
    size: int
    risk_hints: list[str] = field(default_factory=list)


def analyze(path: str | Path) -> BinaryInfo:
    """Detect a binary's format/arch/metadata from its headers.

    Raises FileNotFoundError/OSError if the file does not exist or is unreadable.
    """
    p = Path(path)
    data = p.read_bytes()  # raises FileNotFoundError/OSError naturally
    sha256 = hashlib.sha256(data).hexdigest()
    size = len(data)

    fmt, arch, bits, endian, entry, hints = _detect(data)
    return BinaryInfo(
        path=str(p),
        format=fmt,
        arch=arch,
        bits=bits,
        endian=endian,
        entry=entry,
        sha256=sha256,
        size=size,
        risk_hints=hints,
    )


def _detect(data: bytes) -> tuple[str, str, int | None, str | None, int | None, list[str]]:
    hints: list[str] = []
    if len(data) >= 4 and data[:4] == b"\x7fELF":
        return _detect_elf(data, hints)
    if len(data) >= 2 and data[:2] == b"MZ":
        return _detect_pe(data, hints)
    return ("unknown", "unknown", None, None, None, hints)


# ---------------------------------------------------------------------------
# ELF (manual header parse — no deps)
# ---------------------------------------------------------------------------
def _detect_elf(data: bytes, hints: list[str]) -> tuple[str, str, int | None, str | None, int | None, list[str]]:
    ei_class = data[4]  # 1 = 32-bit, 2 = 64-bit
    ei_data = data[5]  # 1 = little, 2 = big
    bits = 64 if ei_class == 2 else 32 if ei_class == 1 else None
    endian = "little" if ei_data == 1 else "big" if ei_data == 2 else None
    endian_fmt = "<" if endian == "little" else ">"
    # e_machine is a half-word at offset 18 (after 16-byte e_ident + 2-byte e_type)
    machine = struct.unpack_from(endian_fmt + "H", data, 18)[0] if len(data) >= 20 else 0
    arch = ELF_MACHINE_ARCH.get(machine, f"elf_{machine}")
    # entry: e_entry — offset 24 (ELF32) or 24 (ELF64, 8 bytes)
    entry: int | None = None
    if bits == 64 and len(data) >= 32:
        entry = struct.unpack_from(endian_fmt + "Q", data, 24)[0]
    elif bits == 32 and len(data) >= 28:
        entry = struct.unpack_from(endian_fmt + "I", data, 24)[0]
    return ("ELF", arch, bits, endian, entry, hints)


# ---------------------------------------------------------------------------
# PE (prefer pefile; manual fallback)
# ---------------------------------------------------------------------------
def _detect_pe(data: bytes, hints: list[str]) -> tuple[str, str, int | None, str | None, int | None, list[str]]:
    try:
        import pefile  # type: ignore

        pe = pefile.PE(data=data, fast_load=True)
        machine = pe.FILE_HEADER.Machine
        is64 = pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS
        bits = 64 if is64 else 32
        entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        arch = PE_MACHINE_ARCH.get(machine, f"pe_{machine:04x}")
        if pe.FILE_HEADER.Characteristics & IMAGE_FILE_DLL:
            hints.append("is_dll")
        return ("PE", arch, bits, "little", entry, hints)
    except Exception:  # noqa: BLE001 — fall back to manual parse
        return _detect_pe_manual(data, hints)


def _detect_pe_manual(data: bytes, hints: list[str]) -> tuple[str, str, int | None, str | None, int | None, list[str]]:
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    nt = data[e_lfanew:e_lfanew + 4]
    if nt != b"PE\x00\x00":
        return ("unknown", "unknown", None, None, None, hints)
    machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
    opt_magic = struct.unpack_from("<H", data, e_lfanew + 24)[0]
    bits = 64 if opt_magic == 0x20B else 32
    arch = PE_MACHINE_ARCH.get(machine, f"pe_{machine:04x}")
    entry = struct.unpack_from("<I", data, e_lfanew + 24 + 16)[0]
    return ("PE", arch, bits, "little", entry, hints)
