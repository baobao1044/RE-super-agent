"""Synthetic binary fixtures for tests.

These builders emit *minimal-but-valid* ELF and PE header bytes so tests are
deterministic and need no compiler or external binaries. They only need to be
parsed correctly by tools/binary.py (and, where used, pefile/pyelftools).

Builders return raw bytes; `write_*` helpers drop them into a tmp_path.
"""
from __future__ import annotations

import struct

# ---------------------------------------------------------------------------
# ELF (no external dep needed to build/parse the header)
# ---------------------------------------------------------------------------
# ELF e_machine values
EM_386 = 3
EM_X86_64 = 62
EM_ARM = 40
EM_AARCH64 = 183

_ELF_MAGIC = b"\x7fELF"


def build_elf_header(
    bits: int = 64,
    endian: str = "little",
    machine: int = EM_X86_64,
    entry: int = 0x401000,
) -> bytes:
    """Return a minimal valid ELF header (32 or 64-bit) for the given arch.

    endian: 'little' or 'big'.
    """
    ei_data = 1 if endian == "little" else 2
    ei_class = 2 if bits == 64 else 1
    endian_fmt = "<" if endian == "little" else ">"
    # e_ident[16]: magic, class, data, version, osabi, abiversion, pad
    e_ident = _ELF_MAGIC + bytes([ei_class, ei_data, 1, 0]) + b"\x00" * 8
    # ELF64 header after e_ident: H H I Q Q Q I H H H H H H
    # ELF32 header after e_ident: H H I I I I I H H H H
    if bits == 64:
        # e_type=ET_EXEC(2) e_machine e_version(1) e_entry e_phoff e_shoff
        # e_flags e_ehsize e_phentsize e_phnum e_shentsize e_shnum e_shstrndx
        rest = struct.pack(
            endian_fmt + "HHIQQQIHHHHHH",
            2, machine, 1, entry, 64, 0,  # e_phoff=64 (just a plausible nonzero)
            0, 64, 0x38, 0, 0x40, 0, 0,
        )
    else:
        # e_type e_machine e_version e_entry e_phoff e_shoff
        # e_flags e_ehsize e_phentsize e_phnum e_shentsize e_shnum e_shstrndx
        rest = struct.pack(
            endian_fmt + "HHIIIIIHHHHHH",
            2, machine, 1, entry, 52, 0, 0,
            52, 0x20, 0, 0x28, 0, 0,
        )
    return e_ident + rest


def write_elf(tmp_path, name="synth.elf", **kw) -> "object":
    """Write a synthetic ELF to tmp_path/name and return the path object."""
    p = tmp_path / name
    p.write_bytes(build_elf_header(**kw))
    return p


# ---------------------------------------------------------------------------
# PE (MZ stub + PE header, valid enough for pefile + our parser)
# ---------------------------------------------------------------------------
# IMAGE_FILE_MACHINE values
IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_ARM = 0x01C0
IMAGE_FILE_MACHINE_ARM64 = 0xAA64


def build_pe_header(
    bits: int = 64,
    machine: int = IMAGE_FILE_MACHINE_AMD64,
    subsystem: int = 3,  # IMAGE_SUBSYSTEM_WINDOWS_CUI (console)
    is_dll: bool = False,
    entry: int = 0x1000,
) -> bytes:
    """Return a minimal valid PE image (DOS header + NT headers + one section stub).

    Valid enough that pefile.PE(data=...) parses the machine/bits/characteristics.
    """
    # DOS header (64 bytes): e_magic='MZ', e_lfanew at offset 0x3C -> PE header
    pe_offset = 0x80
    dos = bytearray(b"MZ" + b"\x00" * 58)
    dos[0x3C:0x40] = struct.pack("<I", pe_offset)

    is64 = bits == 64
    # IMAGE_FILE_HEADER (20 bytes): machine, nsections, timestamp, sym_off, nsym, opt_size, chars
    characteristics = 0x0102  # EXECUTABLE_IMAGE | 32BIT_MACHINE
    if is_dll:
        characteristics |= 0x2000  # DLL
    file_hdr = struct.pack(
        "<HHIIIHH",
        machine, 1, 0, 0, 0, 0xF0, characteristics,
    )
    # Optional header magic
    opt_magic = 0x20B if is64 else 0x10B
    # Build a minimal optional header (size 0xF0 declared above). We only need
    # magic, size-of-headers, subsystem, characteristics-fields to be sane.
    opt = bytearray(b"\x00" * 0xF0)
    opt[0:2] = struct.pack("<H", opt_magic)
    opt[2:4] = struct.pack("<H", 14)  # MajorLinkerVersion byte + ...
    opt[16:20] = struct.pack("<I", 0x1000)  # SizeOfCode
    if is64:
        # AddressOfEntryPoint at offset 16 of opt header
        opt[16:24] = struct.pack("<II", 0x1000, 0)  # SizeOfCode, SizeOfInitializedData
        # AddressOfEntryPoint @ 0x10, ImageBase @ 0x18 (8 bytes for PE32+)
        opt[0x10:0x14] = struct.pack("<I", entry)
        opt[0x18:0x20] = struct.pack("<Q", 0x140000000)  # ImageBase
        # SectionAlignment / FileAlignment @ 0x20
        opt[0x20:0x28] = struct.pack("<II", 0x1000, 0x200)
        # SizeOfImage @ 0x38, SizeOfHeaders @ 0x3C for PE32+
        opt[0x38:0x40] = struct.pack("<II", 0x3000, 0x200)
        # Subsystem @ 0x5C (PE32+)
        opt[0x5C:0x5E] = struct.pack("<H", subsystem)
        # DllCharacteristics @ 0x5E
        opt[0x5E:0x60] = struct.pack("<H", 0)
    else:
        opt[0x10:0x14] = struct.pack("<I", entry)  # AddressOfEntryPoint
        opt[0x1C:0x20] = struct.pack("<I", 0x400000)  # ImageBase (PE32, 4 bytes)
        opt[0x20:0x28] = struct.pack("<II", 0x1000, 0x200)  # alignments
        opt[0x38:0x40] = struct.pack("<II", 0x3000, 0x200)  # SizeOfImage, SizeOfHeaders
        opt[0x44:0x46] = struct.pack("<H", subsystem)  # Subsystem (PE32 @ 0x44)
        opt[0x46:0x48] = struct.pack("<H", 0)  # DllCharacteristics

    nt_sig = struct.pack("<I", 0x00004550)  # "PE\0\0"
    return bytes(dos) + b"\x00" * (pe_offset - len(dos)) + nt_sig + file_hdr + bytes(opt)


def write_pe(tmp_path, name="synth.exe", **kw):
    p = tmp_path / name
    p.write_bytes(build_pe_header(**kw))
    return p


def build_garbage(n: int = 64, seed: int = 0xC0DE) -> bytes:
    """Reproducible non-binary bytes (not ELF, not PE)."""
    rng = seed
    out = bytearray()
    for _ in range(n):
        rng = (rng * 1103515245 + 12345) & 0xFFFFFFFF
        out.append((rng >> 16) & 0xFF)
    return bytes(out)


def write_garbage(tmp_path, name="garbage.bin", n: int = 64, seed: int = 0xC0DE):
    p = tmp_path / name
    p.write_bytes(build_garbage(n=n, seed=seed))
    return p
