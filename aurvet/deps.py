"""Dependency graph + official-repo membership.

The dependency graph is the silent vector (V5): AUR helpers build and
install a package's AUR-only dependencies without showing them to the
user. We resolve the full depends + makedepends graph and mark which ones
are AUR-only, so the caller can list-check / deep-vet each.

Official membership is read from the local pacman sync databases
(/var/lib/pacman/sync/<repo>/<pkg>-<ver>-<arch>.desc), falling back to
`pacman -Ssq`. No network is involved.
"""

from __future__ import annotations

import glob
import re
import subprocess
from dataclasses import dataclass, field

from .aur import AUR
from .rules import Severity

_VERSION_RE = re.compile(r"[<>!~]=?")

# A malicious PKGBUILD can declare thousands of dependency names; cap the
# graph so a hostile package cannot force unbounded RPC traffic / output.
_BATCH = 100
MAX_DEPS = 400


def bare_name(spec: str) -> str:
    """'python>=3.12' -> 'python'; 'nodejs-lts' -> 'nodejs-lts'."""
    return _VERSION_RE.split(spec, maxsplit=1)[0].strip()


def official_names() -> tuple[set[str], str]:
    """All package names in the local official sync DBs.

    Returns (names, source) where source describes where they came from.
    An empty set with source 'none' means the check was degraded.
    """
    names: set[str] = set()
    for desc in glob.glob("/var/lib/pacman/sync/*/*.desc"):
        try:
            with open(desc, encoding="utf-8", errors="replace") as f:
                for line in f:
                    if line.startswith("pkgname = "):
                        names.add(line.split("=", 1)[1].strip())
                        break
        except OSError:
            continue
    if names:
        return names, "local pacman sync DB"
    try:
        p = subprocess.run(["pacman", "-Ssq"], capture_output=True, text=True, timeout=60)
        if p.returncode == 0:
            return {l.strip() for l in p.stdout.splitlines() if l.strip()}, "pacman -Ssq"
    except (OSError, subprocess.SubprocessError):
        pass
    return set(), "none (official-name checks degraded)"


@dataclass
class DepNode:
    name: str            # bare package name
    kind: str            # official | aur | unknown
    info: dict | None = None  # AUR record when kind == 'aur'
    findings: list = field(default_factory=list)  # lite-check findings


def build_graph(start: str,
                start_info: dict,
                official: set[str]) -> tuple[list[DepNode], dict[str, dict], bool]:
    """BFS over depends + makedepends.

    Returns (aur_only_deps, all_info, truncated). all_info maps every
    resolved AUR package name (including `start`) to its multiinfo record.
    AUR-only deps get lite findings: known-bad list hits are BLOCK-level (a
    malicious dependency corrupts the whole install), other issues are
    surfaced as notes to look at the dep separately. ``truncated`` is True
    when the graph hit ``MAX_DEPS`` distinct dependencies and was cut off.
    """
    all_info: dict[str, dict] = {start: start_info}
    seen: set[str] = {start}
    queue: list[str] = []
    truncated = False
    lockout = False

    def _add(name: str) -> None:
        nonlocal truncated, lockout
        if lockout or name in seen or name in official:
            return
        if len(seen) - 1 >= MAX_DEPS:  # adding this one would exceed the cap
            truncated = True
            lockout = True
            return
        seen.add(name)
        queue.append(name)

    for n in _dep_names(start_info):
        _add(n)

    while queue:
        batch = queue[:_BATCH]
        queue = queue[_BATCH:]
        try:
            fetched = AUR.info(batch)
        except Exception:
            fetched = {}
        for n in batch:
            rec = fetched.get(n)
            all_info[n] = rec or {}
            if rec:
                for m in _dep_names(rec):
                    _add(m)

    nodes: list[DepNode] = []
    for name, rec in all_info.items():
        if name == start:
            continue
        if name in official:
            continue
        kind = "aur" if rec else "unknown"
        node = DepNode(name=name, kind=kind, info=rec or None)
        if not rec:
            node.findings.append({
                "rule": "dep-unresolvable", "severity": Severity.WARN,
                "detail": f"dependency {name!r} is neither in official repos nor "
                          "resolvable via AUR - verify it manually",
            })
        nodes.append(node)
    return nodes, all_info, truncated


def _dep_names(info: dict) -> list[str]:
    out: list[str] = []
    for key in ("Depends", "MakeDepends"):
        for spec in info.get(key, []) or []:
            b = bare_name(spec)
            if b:
                out.append(b)
    return out
