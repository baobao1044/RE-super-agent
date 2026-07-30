"""Custom structural decompiler (bytecode -> source lifter) for eps_deobf.

No installed decompiler supports Python 3.11 here (uncompyle6/decompyle3 refuse
3.11; zrax pycdc needs a C++ toolchain that is absent). This lifter walks the
recovered code objects and emits readable Python source: real signatures for every
def/class, simple assignments/returns where the bytecode maps cleanly, and
annotated bytecode comments where exact source cannot be confidently recovered.

It never executes the code. This is honest RE output: structure is exact, bodies
are best-effort.
"""
from __future__ import annotations

import dis
import marshal
import shutil
import subprocess
import tempfile
import importlib.util
from pathlib import Path

CO_VARARGS = 0x04
CO_VARKEYWORDS = 0x08


def _safe_disasm(code_obj, max_lines=120):
    """Local copy of the safe disassembler to avoid a circular import."""
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


def write_pyc(code_obj, pyc_path):
    """Serialize a code object to a valid .pyc file (matching the running interpreter)."""
    import struct
    import time

    pyc_path = str(pyc_path)
    magic = importlib.util.MAGIC_NUMBER
    flags = 0
    mtime = int(time.time()) & 0xFFFFFFFF
    src_size = 0
    header = magic + struct.pack("<III", flags, mtime, src_size)
    payload = marshal.dumps(code_obj)
    with open(pyc_path, "wb") as fh:
        fh.write(header)
        fh.write(payload)


def _func_signature(code_obj):
    """Reconstruct a def signature string from code-object metadata."""
    vn = code_obj.co_varnames
    n = code_obj.co_argcount
    posonly = getattr(code_obj, "co_posonlyargcount", 0) or 0
    kwonly = getattr(code_obj, "co_kwonlyargcount", 0) or 0
    flags = code_obj.co_flags
    has_varargs = bool(flags & CO_VARARGS)
    has_kwargs = bool(flags & CO_VARKEYWORDS)

    pos = list(vn[:n])
    pos_args = pos[posonly:]
    posonly_args = pos[:posonly]

    idx = n
    varargs = None
    if has_varargs:
        varargs = vn[idx]
        idx += 1
    kwonly_args = list(vn[idx:idx + kwonly])
    idx += kwonly
    kwargs = None
    if has_kwargs:
        kwargs = vn[idx]

    parts = []
    if posonly_args:
        parts.append(", ".join(posonly_args))
        parts.append("/")
    if pos_args:
        parts.append(", ".join(pos_args))
    if varargs is not None:
        parts.append("*" + varargs)
    elif kwonly_args:
        parts.append("*")
    if kwonly_args:
        parts.append(", ".join(kwonly_args))
    if kwargs is not None:
        parts.append("**" + kwargs)
    return ", ".join(p for p in parts if p)


def _const_repr(c):
    """Render a constant for source emission."""
    if hasattr(c, "co_code"):
        return f"<lambda {c.co_qualname or c.co_name}>"
    if isinstance(c, bytes):
        return f"bytes[{len(c)}]"
    if isinstance(c, str) and len(c) > 80:
        return repr(c[:40] + "...")
    try:
        return repr(c)
    except Exception:  # noqa: BLE001
        return "<unreprable>"


def _indent_block(text, indent):
    """Indent every line of a multi-line string (used for nested scopes)."""
    pad = indent
    return "\n".join((pad + ln if ln else ln) for ln in text.splitlines())


def reconstruct_source(code_obj, *, depth=0):
    """Recursively reconstruct readable Python source from a code object.

    Module-level structure (def/class/assign) is recovered exactly from the
    bytecode; function bodies are best-effort with annotated bytecode comments for
    control flow the lifter does not model. Returns a source string.
    """
    ind = "    " * depth
    out = []

    def emit(line):
        out.append(ind + line if line else "")

    co_name = code_obj.co_qualname or code_obj.co_name
    emit(f"# === scope: {co_name} "
         f"(args={code_obj.co_argcount}, locals={code_obj.co_nlocals}, "
         f"stack={code_obj.co_stacksize}) ===")

    consts = list(code_obj.co_consts)
    names = list(code_obj.co_names)
    varnames = tuple(getattr(code_obj, "co_varnames", ()))

    try:
        co2 = code_obj.replace(co_linetable=b"", co_exceptiontable=b"")
    except Exception:  # noqa: BLE001
        co2 = code_obj
    # Guard huge data-table code objects exactly like _safe_disasm: disassembling a
    # 672KB code object yields millions of repetitive LOAD_CONST/APPEND instructions,
    # which would blow up the output to tens of MB. Skip them with a marker comment.
    if len(code_obj.co_code) > 100000:
        emit(f"# [skipped: {len(code_obj.co_code)} bytes of bytecode (data table)]")
        return "\n".join(out)
    try:
        ins = list(dis.get_instructions(co2))
    except Exception:  # noqa: BLE001
        ins = []

    stack = []
    pending_class_code = None  # code_func awaiting name+bases from the CALL
    just_emitted_def = False   # suppress the trailing STORE for a def/class
    ann_count = 0              # annotated bytecode comments emitted this scope
    ANN_LIMIT = 200            # cap verbose bytecode annotations per scope
    i = 0
    n = len(ins)
    while i < n:
        op = ins[i]
        opname = op.opname

        if opname in ("RESUME", "PUSH_NULL", "NOP", "PRECALL", "CACHE", "COPY", "SWAP"):
            # SWAP/COPY are stack shuffles we don't model precisely; ignore for structure.
            if opname in ("COPY", "SWAP") and stack:
                pass  # do not pop; keep best-effort
            i += 1
            continue

        if opname == "LOAD_BUILD_CLASS":
            stack.append("<buildclass>")
            i += 1
            continue

        if opname == "LOAD_CONST":
            c = consts[op.arg] if op.arg is not None and op.arg < len(consts) else None
            stack.append(c)
            i += 1
            continue

        if opname in ("LOAD_NAME", "LOAD_GLOBAL"):
            stack.append(names[op.arg] if op.arg is not None and op.arg < len(names) else f"name{op.arg}")
            i += 1
            continue

        if opname in ("LOAD_FAST", "LOAD_DEREF", "LOAD_CLOSURE"):
            stack.append(varnames[op.arg] if op.arg is not None and op.arg < len(varnames) else f"local{op.arg}")
            i += 1
            continue

        if opname == "MAKE_FUNCTION":
            flags = op.arg or 0
            top = stack.pop() if stack else None
            if flags & 0x01 and stack:
                stack.pop()  # defaults tuple
            if flags & 0x02 and stack:
                stack.pop()  # kwdefaults dict
            code_const = top if hasattr(top, "co_code") else None
            if code_const is not None:
                if "<buildclass>" in stack:
                    # Class body function: defer emission until the CALL supplies
                    # name + bases. Remove the buildclass marker.
                    stack.remove("<buildclass>")
                    pending_class_code = code_const
                    just_emitted_def = True  # suppress the trailing STORE_NAME for now
                else:
                    fname = code_const.co_name
                    sig = _func_signature(code_const)
                    emit(f"def {fname}({sig}):")
                    body = reconstruct_source(code_const, depth=depth + 1)
                    emit(_indent_block(body, ind + "    "))
                    just_emitted_def = True
            i += 1
            continue

        if opname == "CALL":
            if pending_class_code is not None:
                # buildclass(code_func, name, *bases). Stack holds [name, *bases].
                # Pop nargs (arg+1) values; first is the name string, rest are bases.
                nargs = (op.arg or 0) + 1
                args = [stack.pop() for _ in range(min(nargs, len(stack)))]
                args.reverse()
                class_name = args[0] if args and isinstance(args[0], str) else (
                    pending_class_code.co_name)
                bases = [a for a in args[1:] if isinstance(a, str)]
                if bases:
                    emit(f"class {class_name}({', '.join(bases)}):")
                else:
                    emit(f"class {class_name}:")
                body = reconstruct_source(pending_class_code, depth=depth + 1)
                emit(_indent_block(body, ind + "    "))
                pending_class_code = None
                just_emitted_def = True
                i += 1
                continue
            # ordinary call: annotate, drain approximate args
            emit(f"# call: {op.argrepr}")
            nargs = (op.arg or 0) + 1
            for _ in range(min(nargs, len(stack))):
                stack.pop()
            i += 1
            continue

        if opname in ("STORE_NAME", "STORE_GLOBAL"):
            target = names[op.arg] if op.arg is not None and op.arg < len(names) else f"var{op.arg}"
            if just_emitted_def:
                just_emitted_def = False
                i += 1
                continue
            if stack:
                val = stack.pop()
                if hasattr(val, "co_code"):
                    emit(f"# (function/class stored as {target})")
                else:
                    emit(f"{target} = {_const_repr(val)}")
            else:
                emit(f"# STORE {target}")
            i += 1
            continue

        if opname == "STORE_FAST":
            target = varnames[op.arg] if op.arg is not None and op.arg < len(varnames) else f"local{op.arg}"
            if just_emitted_def:
                just_emitted_def = False
                i += 1
                continue
            if stack:
                val = stack.pop()
                if not hasattr(val, "co_code"):
                    emit(f"{target} = {_const_repr(val)}")
                else:
                    emit(f"# {target} = <function>")
            else:
                emit(f"# STORE_FAST {target}")
            i += 1
            continue

        if opname == "RETURN_VALUE":
            if stack:
                val = stack.pop()
                if not hasattr(val, "co_code"):
                    emit(f"return {_const_repr(val)}")
                else:
                    emit("return <function>")
            else:
                emit("return")
            i += 1
            continue

        if opname == "RETURN_CONST":
            c = consts[op.arg] if op.arg is not None and op.arg < len(consts) else None
            emit(f"return {_const_repr(c)}")
            i += 1
            continue

        if opname == "POP_TOP":
            if stack:
                stack.pop()
            i += 1
            continue

        # Anything else (control flow, binary ops, iter): annotate as comment
        # and reset the value-stack guess so later matches don't cascade.
        # Cap the annotations per scope so a single big scope can't blow up the
        # recovered source to tens of MB.
        if ann_count < ANN_LIMIT:
            emit(f"# {op.offset:5} {opname:22} {op.argrepr}")
            ann_count += 1
        elif ann_count == ANN_LIMIT:
            emit(f"# ...[truncated: more bytecode after offset {op.offset}]")
            ann_count += 1
        stack = []
        just_emitted_def = False
        i += 1

    if not out or all(not ln.strip() for ln in out):
        out.append("# (empty scope)")
    return "\n".join(out)


def decompile_code(code_obj, *, workdir=None, decompiler="pycdc", timeout=30):
    """Decompile a code object to Python source.

    Returns the custom structural lifter output (always works on 3.11). If an
    external decompiler is available AND produces output, its output is preferred;
    otherwise the lifted source is returned. Never raises.
    """
    lifted = reconstruct_source(code_obj)
    if not decompiler:
        return lifted
    own_temp = False
    if workdir is None:
        workdir = tempfile.mkdtemp(prefix="re_decomp_")
        own_temp = True
    wd = Path(workdir) if not isinstance(workdir, Path) else workdir
    pyc_path = wd / "recovered.pyc"
    out_path = wd / "recovered.py"
    try:
        try:
            write_pyc(code_obj, pyc_path)
        except Exception:  # noqa: BLE001 -- marshal may fail for custom code objects
            return lifted
        try:
            proc = subprocess.run(
                [decompiler, str(pyc_path)],
                capture_output=True, text=True, timeout=timeout,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return proc.stdout
        except FileNotFoundError:
            return lifted
        except subprocess.TimeoutExpired:
            return lifted
        except Exception:  # noqa: BLE001
            return lifted
        try:
            proc2 = subprocess.run(
                [decompiler, "-o", str(out_path), str(pyc_path)],
                capture_output=True, text=True, timeout=timeout,
            )
            txt = out_path.read_text(encoding="utf-8", errors="replace") if out_path.exists() else ""
            if txt.strip():
                return txt
        except Exception:  # noqa: BLE001
            pass
    finally:
        if own_temp:
            shutil.rmtree(wd, ignore_errors=True)
    return lifted


def decompile_python_source(path, *, workdir=None, decompiler="pycdc", timeout=60):
    """End-to-end: deserialize the protected file -> decompile -> return Python source.

    Returns a dict: {available, source, decompiler, protector, ...} or
    {available: False, error: ...} on failure. Never executes the protected code.
    """
    from tools.eps_deobf import deobfuscate  # lazy import avoids a cycle at load time

    target = Path(path)
    if not target.exists():
        return {"available": False, "error": f"target not found: {path}"}
    try:
        code_obj, info = deobfuscate(path)
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "error": f"deobfuscation failed: {type(exc).__name__}: {exc}"}

    source = decompile_code(code_obj, workdir=workdir, decompiler=decompiler, timeout=timeout)
    # Detect whether we got external-decompiler output or the lifter fallback.
    used = decompiler if (decompiler and not source.lstrip().startswith("# === scope:")) else "custom-lifter"
    return {
        "available": True,
        "source": source,
        "decompiler": used,
        "protector": "enphysic.pro / Ngocuyencoder",
        "python_version": list(info["python"]),
        "blob_index": info["blob_index"],
        "source_chars": len(source),
    }
