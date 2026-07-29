"""Logging setup. Thin wrapper around stdlib logging with an optional rich handler
for nicer console output in the CLI. Safe to call multiple times.
"""
from __future__ import annotations

import logging
from pathlib import Path


def setup_logging(level: str | int = "INFO", log_dir: str | Path | None = None) -> logging.Logger:
    """Configure root logging: console + optional file handler in `log_dir`.

    Idempotent: re-calling replaces handlers rather than stacking duplicates.
    """
    root = logging.getLogger()
    # Clear existing handlers to avoid stacking on re-config.
    for h in list(root.handlers):
        root.removeHandler(h)

    lvl = level if isinstance(level, int) else getattr(logging, str(level).upper(), logging.INFO)
    root.setLevel(lvl)
    fmt = logging.Formatter("[%(asctime)s] %(levelname)-7s %(name)s: %(message)s", "%H:%M:%S")

    try:
        from rich.logging import RichHandler  # type: ignore

        console = RichHandler(rich_tracebacks=True, show_path=False, markup=False)
        console.setFormatter(logging.Formatter("%(message)s"))
        root.addHandler(console)
    except Exception:  # noqa: BLE001 — rich optional
        sh = logging.StreamHandler()
        sh.setFormatter(fmt)
        root.addHandler(sh)

    if log_dir:
        ld = Path(log_dir)
        ld.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(ld / "re-agent.log", encoding="utf-8")
        fh.setFormatter(fmt)
        root.addHandler(fh)

    logging.getLogger("urllib3").setLevel(logging.WARNING)
    return root
