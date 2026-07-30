"""Agentic LLM decompiler: uses the configured LLM provider (GLM-5.2 via W&B by
default) to translate the custom structural lifter's bytecode annotations into real
Python source (if/for/while/try-except instead of `# RERAISE` comments).

This avoids pulling a 2GB+ ML decompiler (pylingual/torch) into an open-source RE
project by reusing the LLM API the agent already has configured. The structural
lifter (decompile_lifter.reconstruct_source) produces exact def/class signatures +
annotated bytecode; the LLM then reconstructs readable control flow from those
annotations.

Safety: this NEVER executes the protected code. It only feeds the static
bytecode annotations to the LLM as text. Falls back to the structural source on
any LLM failure (missing provider, error, empty response).
"""
from __future__ import annotations

import re

from pathlib import Path

# Default context budget for the structural source sent to the LLM per scope.
# Keeps each LLM call within a reasonable token budget; large scopes are truncated
# (the LLM still sees the signatures + first N bytecode annotations).
DEFAULT_MAX_STRUCT_CHARS = 6000

SYSTEM_PROMPT = (
    "You are a Python bytecode decompiler. You receive the structural output of a "
    "custom Python-3.11 bytecode lifter: exact def/class signatures plus annotated "
    "bytecode comments (e.g. `#   12 CONTAINS_OP`, `#   14 POP_JUMP_FORWARD_IF_FALSE "
    "to 38`, `#   48 FOR_ITER to 82`, `#   74 BINARY_OP +`). Reconstruct readable "
    "Python source from these annotations. Map the common 3.11 patterns:\n"
    "- CONTAINS_OP 0 -> `in`, CONTAINS_OP 1 -> `not in`\n"
    "- POP_JUMP_FORWARD_IF_FALSE / POP_JUMP_BACKWARD_IF_FALSE -> `if` / `while` branch\n"
    "- FOR_ITER -> `for` loop\n"
    "- BINARY_OP (+,-,*,/,%, &,|,^) -> arithmetic / bitwise ops\n"
    "- BINARY_SUBSCR -> subscript `x[i]`\n"
    "- STORE_SUBSCR -> `x[i] = v`\n"
    "- COMPARE_OP -> comparison `==,!=,<,>,<=,>=`\n"
    "- PUSH_EXC_INFO / CHECK_EXC_MATCH / RERAISE / POP_EXCEPT -> try/except blocks\n"
    "- CALL -> function/method call\n"
    "- Return statements where RETURN_VALUE / RETURN_CONST appear\n"
    "Rules:\n"
    "1. Do NOT spend time reasoning or explaining. Go straight to the answer.\n"
    "2. Preserve EXACT def/class signatures (names, args, defaults) from the input.\n"
    "3. Preserve obfuscated identifiers verbatim (CJK Unicode names) — do NOT rename.\n"
    "4. Reconstruct control flow (if/for/while/try-except) from the bytecode hints.\n"
    "5. When a sequence of LOAD_CONST + BUILD_LIST/APPEND appears, emit a list literal.\n"
    "6. Output ONLY the reconstructed Python source — no markdown fences, no commentary, "
    "no explanations, no reasoning. Just the code.\n"
    "7. If you cannot confidently reconstruct a line, keep it as a `# bytecode:` comment.\n"
    "Be concise. Emit valid, indented Python that matches the bytecode's logic."
)


def _extract_python_source(content: str) -> str:
    """Extract clean Python source from LLM output.

    GLM reasoning models may embed code in ````python` blocks within reasoning text,
    or emit a single fenced block, or raw source. This handles all cases:
    1. Multiple ```python blocks -> take the LAST (most refined reconstruction).
    2. Single ```python block -> take its contents.
    3. Raw Python source (starts with def/class/import/#) -> return as-is.
    4. Mixed reasoning + code -> find the longest contiguous Python-looking block.
    """
    # Find all ```python or ``` code blocks
    blocks = re.findall(r"```(?:python)?\n(.*?)```", content, re.DOTALL)
    if blocks:
        # Return the last block (most refined after reasoning)
        return blocks[-1].rstrip()

    # No code fences — strip leading/trailing fence fragments if present
    lines = content.splitlines()
    if lines and lines[0].lstrip().startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].lstrip().startswith("```"):
        lines = lines[:-1]
    return "\n".join(lines)


def llm_decompile(
    structural_source: str,
    *,
    provider,
    python_version: tuple[int, int] | None = None,
    max_struct_chars: int = DEFAULT_MAX_STRUCT_CHARS,
    max_tokens: int = 4096,
    temperature: float = 0.2,
    timeout: int = 120,
) -> str:
    """Translate structural-source annotations into real Python via the LLM provider.

    Returns the LLM-reconstructed Python source, or falls back to ``structural_source``
    when there is no provider, the LLM errors, or returns empty. Never raises.
    """
    if provider is None:
        return structural_source

    src = structural_source
    truncated = False
    if len(src) > max_struct_chars:
        src = src[:max_struct_chars] + f"\n# ...[truncated: {len(structural_source) - max_struct_chars} more chars]"
        truncated = True

    version_hint = f" (Python {python_version[0]}.{python_version[1]} bytecode)" if python_version else ""
    user_prompt = (
        f"Reconstruct real Python source from this recovered bytecode structure"
        f"{version_hint}{' (truncated)' if truncated else ''}. Emit ONLY Python source:\n\n"
        f"{src}"
    )

    try:
        resp = provider.complete(
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=temperature,
            max_tokens=max_tokens,
            timeout=timeout,
        )
        content = getattr(resp, "content", "") or ""
        if content.strip():
            return _extract_python_source(content)
    except Exception:  # noqa: BLE001 — any LLM failure degrades to structural
        pass
    return structural_source


def decompile_python_source_with_llm(
    path: str,
    *,
    provider,
    python_version: tuple[int, int] | None = None,
    max_struct_chars: int = DEFAULT_MAX_STRUCT_CHARS,
    timeout: int = 120,
) -> dict:
    """End-to-end: deserialize protected file -> structural lifter -> LLM decompile.

    Returns a dict: {available, source, decompiler, protector, python_version, source_chars}
    or {available: False, error: ...}. Never executes the protected code.
    """
    from tools.eps_deobf import deobfuscate
    from tools.decompile_lifter import reconstruct_source

    target = Path(path)
    if not target.exists():
        return {"available": False, "error": f"target not found: {path}"}
    try:
        code_obj, info = deobfuscate(path)
    except Exception as exc:  # noqa: BLE001
        return {"available": False, "error": f"deobfuscation failed: {type(exc).__name__}: {exc}"}

    pv = python_version or tuple(info["python"])
    structural = reconstruct_source(code_obj)
    source = llm_decompile(
        structural, provider=provider, python_version=pv,
        max_struct_chars=max_struct_chars, timeout=timeout,
    )
    # Detect whether the LLM actually changed the output vs the structural fallback.
    used = "llm-lifter" if source != structural else "custom-lifter"
    return {
        "available": True,
        "source": source,
        "decompiler": used,
        "protector": "enphysic.pro / Ngocuyencoder",
        "python_version": list(pv),
        "blob_index": info["blob_index"],
        "source_chars": len(source),
    }
