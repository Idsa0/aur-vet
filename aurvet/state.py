"""Cleared-state bookkeeping.

``--clear`` records the exact file contents (sha256 per file) and mirror
commit a package was reviewed at. Subsequent runs compare against it:
changed files are diffed and new committers since the cleared commit are
listed. This is what makes "safe" keep meaning something across updates.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import datetime, timezone

SCHEMA_VERSION = 1


def default_state_path() -> str:
    base = os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
    return os.path.join(base, "aurvet", "state.json")


def load(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {"version": SCHEMA_VERSION, "packages": {}}
    data.setdefault("version", SCHEMA_VERSION)
    data.setdefault("packages", {})
    return data


def save(path: str, state: dict) -> None:
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    tmp = path + ".tmp"
    # The state file reveals which AUR packages the user vets and when:
    # keep it owner-only regardless of umask (covers pre-existing files
    # created earlier with a permissive mode via fchmod).
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            fd = None  # ownership passed to fdopen
            json.dump(state, f, indent=2, sort_keys=True)
            f.write("\n")
    finally:
        if fd is not None:
            os.close(fd)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def file_hashes(files: dict[str, bytes]) -> dict[str, str]:
    return {p: hashlib.sha256(data).hexdigest() for p, data in sorted(files.items())}


def mark_cleared(state: dict, name: str, git_sha: str, files: dict[str, bytes],
                 verdict: str, extra: dict | None = None) -> None:
    entry = {
        "cleared_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "git_sha": git_sha,
        "files": file_hashes(files),
        "verdict": verdict,
    }
    if extra:
        entry.update(extra)
    state["packages"][name] = entry


def get_cleared(state: dict, name: str) -> dict | None:
    return state["packages"].get(name)


def changed_files(cleared: dict, files: dict[str, bytes]) -> list[str]:
    """Paths (sorted) whose sha256 differs from the cleared state."""
    cur = file_hashes(files)
    old = cleared.get("files", {})
    out = [p for p in set(old) | set(cur) if old.get(p) != cur.get(p)]
    return sorted(out)
