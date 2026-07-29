"""Tests for tools/binary.py — binary metadata detection (PE/ELF format, arch, risk hints).

These tests use synthetic fixtures (tests/fixtures/binary_builders.py) so they are
deterministic and need no compiler or external binaries.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

# make the project root importable when run from anywhere
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
TESTS = ROOT / "tests"
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from fixtures import binary_builders as bb  # noqa: E402
from tools.binary import analyze, BinaryInfo  # noqa: E402


# ---------------------------------------------------------------------------
# format + arch detection
# ---------------------------------------------------------------------------
def test_detect_elf64_x86_64(tmp_path):
    p = bb.write_elf(tmp_path, name="x86_64.elf", bits=64, machine=bb.EM_X86_64, entry=0x401000)
    info = analyze(p)
    assert info.format == "ELF"
    assert info.arch == "x86_64"
    assert info.bits == 64
    assert info.endian == "little"


def test_detect_elf32_x86(tmp_path):
    p = bb.write_elf(tmp_path, name="x86.elf", bits=32, machine=bb.EM_386)
    info = analyze(p)
    assert info.format == "ELF"
    assert info.arch == "x86"
    assert info.bits == 32
    assert info.endian == "little"


def test_detect_pe64_amd64(tmp_path):
    p = bb.write_pe(tmp_path, name="amd64.exe", bits=64, machine=bb.IMAGE_FILE_MACHINE_AMD64)
    info = analyze(p)
    assert info.format == "PE"
    assert info.arch == "x86_64"
    assert info.bits == 64
    assert info.endian == "little"


def test_detect_pe32_i386(tmp_path):
    p = bb.write_pe(tmp_path, name="i386.exe", bits=32, machine=bb.IMAGE_FILE_MACHINE_I386)
    info = analyze(p)
    assert info.format == "PE"
    assert info.arch == "x86"
    assert info.bits == 32


def test_detect_unknown_format(tmp_path):
    p = bb.write_garbage(tmp_path, name="blob.bin")
    info = analyze(p)
    assert info.format == "unknown"
    assert info.arch == "unknown"
    assert info.bits is None


# ---------------------------------------------------------------------------
# metadata
# ---------------------------------------------------------------------------
def test_sha256_and_size_set(tmp_path):
    p = bb.write_elf(tmp_path, name="h.elf", bits=64, machine=bb.EM_X86_64)
    raw = p.read_bytes()
    info = analyze(p)
    assert info.sha256 == hashlib.sha256(raw).hexdigest()
    assert info.size == len(raw)


def test_entry_point_captured(tmp_path):
    p = bb.write_elf(tmp_path, name="e.elf", bits=64, machine=bb.EM_X86_64, entry=0x401234)
    info = analyze(p)
    assert info.entry == 0x401234


def test_path_recorded(tmp_path):
    p = bb.write_pe(tmp_path, name="p.exe", bits=64, machine=bb.IMAGE_FILE_MACHINE_AMD64)
    info = analyze(p)
    assert Path(info.path).name == "p.exe"


# ---------------------------------------------------------------------------
# risk hints (basic heuristics — no real malware needed)
# ---------------------------------------------------------------------------
def test_pe_dll_flagged_as_dll(tmp_path):
    p = bb.write_pe(tmp_path, name="lib.dll", bits=64, machine=bb.IMAGE_FILE_MACHINE_AMD64, is_dll=True)
    info = analyze(p)
    assert "is_dll" in info.risk_hints


def test_missing_file_raises(tmp_path):
    with pytest.raises((FileNotFoundError, OSError)):
        analyze(tmp_path / "does_not_exist.bin")
