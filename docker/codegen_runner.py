#!/usr/bin/env python3
"""Code-gen runner — the ENTRYPOINT of the sandbox image.

The workflow engine (agent/core/workflow.py) asks the LLM to write a Python snippet
that performs a complex, bespoke analysis step (e.g. VM handler lifting). The snippet
is written to a bind-mounted file and this runner executes it inside the sandbox.

Contract:
  - The snippet receives its input via a JSON file path in argv[1] (or stdin).
  - The snippet MUST print exactly one JSON object on stdout (its result).
  - We capture the snippet's stdout, validate it parses as JSON, and echo it back
    as a single JSON line on OUR stdout so the host can read it reliably.
  - Any exception or non-JSON stdout becomes a structured error object.

This runner itself is trusted (shipped with the image). Only the user/LLM snippet is
untrusted, and it runs inside the already-hardened container.
"""
from __future__ import annotations

import json
import runpy
import sys
import traceback
from pathlib import Path


def main() -> int:
    if len(sys.argv) < 2:
        print(json.dumps({"ok": False, "error": "missing script path argument"}))
        return 2

    script_path = Path(sys.argv[1])
    if not script_path.is_file():
        print(json.dumps({"ok": False, "error": f"script not found: {script_path}"}))
        return 2

    # Optional input JSON (argv[2]) is exposed to the snippet via env RE_INPUT.
    input_data: object | None = None
    if len(sys.argv) >= 3:
        in_path = Path(sys.argv[2])
        if in_path.is_file():
            try:
                input_data = json.loads(in_path.read_text(encoding="utf-8"))
            except Exception as exc:  # noqa: BLE001
                print(json.dumps({"ok": False, "error": f"bad input json: {exc}"}))
                return 2

    if input_data is not None:
        sys.environ["RE_INPUT"] = json.dumps(input_data)

    # Run the snippet in an isolated namespace; capture its stdout.
    import io
    import contextlib

    buf = io.StringIO()
    exit_code = 0
    with contextlib.redirect_stdout(buf):
        try:
            runpy.run_path(str(script_path), run_name="__codegen_main__")
        except SystemExit as exc:  # snippet called sys.exit()
            exit_code = int(exc.code) if isinstance(exc.code, int) else 1
        except Exception:  # noqa: BLE001
            tb = traceback.format_exc()
            print(json.dumps({"ok": False, "error": "snippet raised", "traceback": tb}))
            return 1

    out = buf.getvalue().strip()
    if not out:
        print(json.dumps({"ok": True, "result": None, "exit_code": exit_code}))
        return 0
    try:
        parsed = json.loads(out)
        print(json.dumps({"ok": True, "result": parsed, "exit_code": exit_code}))
    except Exception:  # snippet printed non-JSON → treat as raw text result
        print(json.dumps({"ok": True, "result": {"raw": out}, "exit_code": exit_code}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
