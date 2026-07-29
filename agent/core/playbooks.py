"""Bundled playbook templates — shipped workflow DAGs keyed by binary type.

A successful or analyst-curated workflow is saved as a parametrized template (crackme /
packed_vm / malware / ctf). The Supervisor falls back to these when the LLM cannot
synthesize a valid DAG, and seeds the user's playbooks directory with them on first run so
the agent works out-of-the-box without a cloud LLM round-trip.

Each template is a status-agnostic DAG (all nodes 'pending', no outputs) that the engine
loads and executes. The bundled JSON files live next to this module.
"""
from __future__ import annotations

import json
import shutil
from importlib import resources
from pathlib import Path

# Binary types that ship with a bundled playbook template.
BUNDLED_PLAYBOOKS = ("crackme", "packed_vm", "malware", "ctf")


def _bundled_dir() -> Path:
    # The bundled JSON templates live in the sibling 'playbooks' directory next to this
    # module (agent/core/playbooks/*.json), not in the module's own directory.
    return Path(__file__).resolve().parent / "playbooks"


def load_template(name: str) -> dict:
    """Return the raw JSON dict of a bundled playbook template (validates the name)."""
    if name not in BUNDLED_PLAYBOOKS:
        raise FileNotFoundError(f"no bundled playbook '{name}'; known: {BUNDLED_PLAYBOOKS}")
    path = _bundled_dir() / f"{name}.json"
    return json.loads(path.read_text(encoding="utf-8"))


def seed_playbooks_dir(target_dir: str | Path, *, overwrite: bool = False) -> list[str]:
    """Copy the bundled playbook templates into `target_dir` (created if missing).

    By default does not overwrite an existing user-customized template. Returns the list
    of playbook names now present in the target directory.
    """
    target = Path(target_dir)
    target.mkdir(parents=True, exist_ok=True)
    seeded: list[str] = []
    for name in BUNDLED_PLAYBOOKS:
        dst = target / f"{name}.json"
        if dst.exists() and not overwrite:
            continue
        shutil.copyfile(_bundled_dir() / f"{name}.json", dst)
        seeded.append(name)
    return seeded


def list_bundled() -> list[str]:
    return list(BUNDLED_PLAYBOOKS)
