"""Integration tests for cli.build_supervisor tool-registries — routing to real backends.

Stage 9d: proves the CLI wiring routes each specialist's tool name to the real MCP server
tool_* function (pure-logic backends degrade gracefully). Each registry lambda is invoked
with a synthetic binary and must return a dict (no AttributeError / import error). This
catches broken wiring (wrong tool name / signature drift) that unit tests on the
specialists miss.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
TESTS = ROOT / "tests"
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from fixtures import binary_builders as bb  # noqa: E402
from agent import cli  # noqa: E402


@pytest.fixture
def binary(tmp_path):
    p = tmp_path / "target.exe"
    p.write_bytes(bb.build_pe_header(bits=64, machine=bb.IMAGE_FILE_MACHINE_AMD64))
    return str(p)


def test_malware_registry_routes_to_real_tools(binary):
    reg = cli._malware_registry(binary)
    r = reg["risk_scan"]({"path": binary})
    assert isinstance(r, dict)
    assert "risk_level" in r
    s = reg["extract_strings"]({"path": binary, "min_len": 4})
    assert isinstance(s, dict)
    assert "strings" in s


def test_static_registry_routes_to_real_tools(binary):
    reg = cli._static_registry(binary)
    fns = reg["list_functions"]({"path": binary})
    assert isinstance(fns, dict) or isinstance(fns, list)
    s = reg["strings"]({"path": binary})
    assert isinstance(s, dict) or isinstance(s, list)
    sym = reg["resolve_symbol"]({"path": binary, "name": "main"})
    assert isinstance(sym, dict)
    pat = reg["search_pattern"]({"path": binary, "pattern": "MZ"})
    assert isinstance(pat, dict) or isinstance(pat, list)


def test_dynamic_registry_routes_to_real_tools(binary):
    reg = cli._dynamic_registry(binary)
    aa = reg["detect_anti_analysis"]({"path": binary})
    assert isinstance(aa, dict)
    assert "anti_debug" in aa or "hints" in aa
    rh = reg["recommend_handling"]({"anti_hints": ["anti_debug"]})
    assert isinstance(rh, dict)


def test_symbolic_registry_routes_to_real_tools(binary):
    reg = cli._symbolic_registry(binary)
    lp = reg["load_project"]({"path": binary})
    assert isinstance(lp, dict)
    # find_input_satisfying degrades to a pure brute-force when angr is absent
    fis = reg["find_input_satisfying"]({"predicate_str": "lambda x: bytes(x) == b'AB'",
                                         "input_length": 2,
                                         "alphabet_start": 65, "alphabet_end": 67})
    assert isinstance(fis, dict)


def test_deobf_registry_routes_to_real_tools(binary):
    reg = cli._deobf_registry(binary)
    lt = reg["load_target"]({"path": binary})
    assert isinstance(lt, dict)
    spec = reg["build_vm_spec"]({"dispatch_addr": 0x402000, "handlers": [
        {"opcode": 0x01, "name": "vm_add", "effects": "reg[A]+=reg[B]"}]})
    assert isinstance(spec, dict) and "opcodes" in spec
    dis = reg["disassemble_vm_bytecode"]({"spec": spec, "bytecode": "\x01"})
    assert isinstance(dis, list)
    assert dis[0]["opcode_name"] == "vm_add"
    rn = reg["reconstruct_native"]({"trace": [{"pc": 0x401000, "mnemonic": "mov"}]})
    assert isinstance(rn, list)
