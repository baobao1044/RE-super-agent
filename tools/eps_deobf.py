"""Safe static deobfuscator for enphysic.pro / Ngocuyencoder protected Python files.

Replicates the protector's custom code-object deserializer, but instead of exec()-ing the
reconstructed code, it disassembles it with `dis` and dumps constants/names — pure
inspection, the untrusted code is NEVER executed.

Protection scheme (from the runtime stub):
  payload = lzma.decompress(base64.b64decode(_B['p']))
  stream = BytesIO(payload)
  pool_count = read u32        -> string/constant pool (each entry is itself a serialized node)
  pool = [stream.read(read_u32()) for _ in range(pool_count)]
  blobs = [stream.read(read_u32()) for _ in range(4)]   # one per Python 3.11/3.12/3.13/3.14
  code_obj = deserialize(BytesIO(blobs[version_index]))
  exec(code_obj, globals())   # <- the protector does this; WE DO NOT
"""
import ast
import dis
import io
import lzma
import base64
import marshal
import os
import shutil
import subprocess
import sys
import tempfile
import importlib.util
from pathlib import Path


def read_u32(s):
    return int.from_bytes(s.read(4), 'little', signed=True)


def make_deserializer(code_type, pool):
    """Return the recursive _epsnode function bound to `pool`."""
    def node(s):
        t = s.read(1)
        if t == b'c':
            # code object: 19 fields matching the protector's _epsCT(...) call
            args = [
                read_u32(s),  # co_argcount
                read_u32(s),  # co_posonlyargcount
                read_u32(s),  # co_kwonlyargcount
                read_u32(s),  # co_nlocals
                read_u32(s),  # co_stacksize
                read_u32(s),  # co_flags
                node(s),      # co_code
                tuple(node(s) for _ in range(read_u32(s))),  # co_consts
                tuple(node(s) for _ in range(read_u32(s))),  # co_names
                tuple(node(s) for _ in range(read_u32(s))),  # co_varnames
                node(s),      # co_filename
                node(s),      # co_name
                node(s),      # co_qualname
                read_u32(s),  # co_firstlineno
                node(s),      # co_linetable
                node(s),      # co_exception_handlers (3.11+)
                tuple(node(s) for _ in range(read_u32(s))),  # ?
                tuple(node(s) for _ in range(read_u32(s))),  # ?
            ]
            return code_type(*args)
        if t == b't':
            return tuple(node(s) for _ in range(read_u32(s)))
        if t == b'r':
            return frozenset(node(s) for _ in range(read_u32(s)))
        if t == b'l':
            return slice(node(s), node(s), node(s))
        if t == b'P':
            return node(io.BytesIO(pool[read_u32(s)]))
        if t == b's':
            return s.read(read_u32(s)).decode()
        if t == b'b':
            return s.read(read_u32(s))
        if t == b'i':
            return int(s.read(read_u32(s)).decode())
        if t == b'g':
            return float(s.read(read_u32(s)).decode())
        if t == b'x':
            return complex(node(s), node(s))
        if t == b'N':
            return None
        if t == b'T':
            return True
        if t == b'F':
            return False
        raise ValueError(f"unknown node tag {t!r} at offset {s.tell()-1}")
    return node


def extract_payload_blob(path):
    """Parse the protected file and return the base64 string in _B['p'] (without exec)."""
    src = open(path, 'r', encoding='utf-8', errors='replace').read()
    # Find the _B = {'p': '...'} literal via AST on just that line (line 10).
    line10 = src.splitlines()[9]
    mod = ast.parse(line10)
    assign = mod.body[0]
    # _B = {'p': '<b64>'}  -> return the VALUE paired with key 'p'
    dict_lit = assign.value
    for k, v in zip(dict_lit.keys, dict_lit.values):
        if isinstance(k, ast.Constant) and k.value == 'p':
            return v.value
    raise ValueError("could not find _B['p'] payload")


def deobfuscate(path, *, dump_dir=None, max_disasm_lines=4000):
    """Return (code_obj, info) for the current Python version's blob. Never execs."""
    b64 = extract_payload_blob(path)
    raw = lzma.decompress(base64.b64decode(b64))
    stream = io.BytesIO(raw)

    pool_count = read_u32(stream)
    pool = [stream.read(read_u32(stream)) for _ in range(pool_count)]
    blobs = [stream.read(read_u32(stream)) for _ in range(4)]

    # Version index: 0->3.14, 1->3.13, 2->3.12, 3->3.11
    vi = sys.version_info[:2]
    idx = { (3,14):0, (3,13):1, (3,12):2, (3,11):3 }.get(vi, 3)

    code_type = type((lambda: 0).__code__)
    node = make_deserializer(code_type, pool)
    code_obj = node(io.BytesIO(blobs[idx]))
    return code_obj, {"pool_count": pool_count, "blob_index": idx, "python": vi,
                      "blob_sizes": [len(b) for b in blobs]}


def _safe_disasm(code_obj, max_lines=120):
    """Disassemble a reconstructed code object without hanging on malformed linetables.

    Skips disassembly entirely for very large code objects (e.g. a 672KB data-table
    lambda) — dis on those takes too long and yields only repetitive LOAD_CONST/APPEND.
    """
    if len(code_obj.co_code) > 100000:
        return [f"...[skipped: {len(code_obj.co_code)} bytes of bytecode (data table)]"]
    try:
        co2 = code_obj.replace(co_linetable=b"", co_exceptiontable=b"")
    except Exception:  # noqa: BLE001
        co2 = code_obj
    lines = []
    try:
        for ins in dis.get_instructions(co2):
            lines.append(f"{ins.offset:5} {ins.opname:22} {ins.argrepr}")
            if len(lines) >= max_lines:
                lines.append(f"...[truncated: more instructions after offset {ins.offset}]")
                break
    except Exception:  # noqa: BLE001
        return lines if lines else []
    return lines


def summarize_code(code_obj, depth=0, out=None):
    """Recursively disassemble + summarize a code object and its nested code objects."""
    if out is None:
        out = []
    indent = "  " * depth
    out.append(f"{indent}=== code: {code_obj.co_qualname or code_obj.co_name} "
               f"@ {code_obj.co_filename}:{code_obj.co_firstlineno} "
               f"(args={code_obj.co_argcount}, nlocals={code_obj.co_nlocals}, "
               f"stack={code_obj.co_stacksize}) ===")
    out.append(f"{indent}names: {code_obj.co_names}")
    # constants (truncate long bytes)
    consts = []
    for c in code_obj.co_consts:
        if isinstance(c, bytes) and len(c) > 80:
            consts.append(f"bytes[{len(c)}]:{c[:40]!r}...")
        elif isinstance(c, str) and len(c) > 200:
            consts.append(f"str[{len(c)}]:{c[:80]!r}...")
        else:
            consts.append(c)
    out.append(f"{indent}consts: {consts}")
    # bytecode disassembly (linetable-neutralized to avoid hangs)
    for ln in _safe_disasm(code_obj):
        out.append(f"{indent}  {ln}")
    out.append(f"{indent}---")
    # recurse into nested code objects in consts
    for c in code_obj.co_consts:
        if hasattr(c, 'co_code'):  # nested code object
            summarize_code(c, depth + 1, out)
    return out


def recover_source_summary(path, *, max_disasm_lines=80, max_const_chars=200):
    """Return a JSON-serializable summary of the recovered code object (no execution).

    Walks the top-level code object + nested code objects, returning a structured dict
    with name/args/consts/names + a capped bytecode disassembly per scope. Used by the
    deobfuscation MCP server tool so the agent can inspect recovered Python bytecode
    without ever running the protected code.
    """
    code_obj, info = deobfuscate(path)
    summary = {
        "protector": "enphysic.pro / Ngocuyencoder",
        "pool_count": info["pool_count"],
        "python_version": list(info["python"]),
        "blob_index": info["blob_index"],
        "blob_sizes": info["blob_sizes"],
        "top_code": _scope_summary(code_obj, max_disasm_lines, max_const_chars),
    }
    return summary


def _scope_summary(code_obj, max_disasm_lines, max_const_chars):
    """Summarize one scope; recurse into nested code objects in co_consts."""
    def _trunc(v):
        if isinstance(v, bytes):
            return f"bytes[{len(v)}]:{v[:max_const_chars]!r}" + (f"..." if len(v) > max_const_chars else "")
        if isinstance(v, str) and len(v) > max_const_chars:
            return v[:max_const_chars] + f"...[+{len(v)-max_const_chars}]"
        if isinstance(v, (tuple, frozenset, slice)):
            r = repr(v)
            return r if len(r) <= max_const_chars else r[:max_const_chars] + "..."
        return v
    s = {
        "name": code_obj.co_qualname or code_obj.co_name,
        "filename": code_obj.co_filename,
        "firstline": code_obj.co_firstlineno,
        "argcount": code_obj.co_argcount,
        "nlocals": code_obj.co_nlocals,
        "stacksize": code_obj.co_stacksize,
        "names": list(code_obj.co_names),
        "consts": [_trunc(c) if not hasattr(c, "co_code") else f"<code {c.co_qualname or c.co_name}>"
                   for c in code_obj.co_consts[:50]]
                   + ([f"...[+{len(code_obj.co_consts)-50} more consts]"] if len(code_obj.co_consts) > 50 else []),
        "disassembly": _safe_disasm(code_obj, max_lines=max_disasm_lines),
    }
    nested = [c for c in code_obj.co_consts if hasattr(c, "co_code")]
    if nested:
        s["nested"] = [_scope_summary(c, max_disasm_lines, max_const_chars) for c in nested]
    return s


# ---------------------------------------------------------------------------
# Full-source decompilation (re-exported from the standalone lifter module).
#
# No installed decompiler supports Python 3.11 here (uncompyle6/decompyle3 refuse
# 3.11; zrax pycdc needs a C++ toolchain that is absent). The standalone lifter in
# tools/decompile_lifter.py walks the recovered code objects and emits readable
# Python source (exact structure, best-effort bodies). These names are re-exported
# here for backward compatibility with callers importing from tools.eps_deobf.
# ---------------------------------------------------------------------------
from tools.decompile_lifter import (  # noqa: E402,F401
    write_pyc, reconstruct_source, decompile_code, decompile_python_source,
)


def _placeholder_decompile_code(code_obj, *, workdir=None, decompiler="pycdc", timeout=30):
    """[deprecated] Use ``decompile_code`` from tools.decompile_lifter instead.

    Kept as a stub so the old block is replaced; the real implementation lives in
    tools.decompile_lifter and is re-exported above. This stub is never called.
    """
    raise RuntimeError("use tools.decompile_lifter.decompile_code")


if __name__ == "__main__":
    import sys
    code_obj, info = deobfuscate(sys.argv[1])
    print(f"pool_count={info['pool_count']} blob_index={info['blob_index']} "
          f"python={info['python']} blob_sizes={info['blob_sizes']}")
    print()
    print("\n".join(summarize_code(code_obj)))
