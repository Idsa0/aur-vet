"""Orchestration: resolve names, vet packages, recurse into AUR deps,
compare against cleared state."""

from __future__ import annotations

import difflib
from dataclasses import dataclass, field

from . import deps as depsmod
from . import pkgbuild as pb
from . import rules
from . import state as statemod
from .aur import AUR, HttpError
from .lists import BadLists
from .report import PkgReport, Verdict, finding_verdict
from .rules import Finding, Severity


@dataclass
class Opts:
    deep: bool = False
    max_depth: int = 3
    no_refresh: bool = False
    show_diff: bool = True
    clear: bool = False
    watch: bool = False


@dataclass
class Env:
    bad: BadLists
    official: set[str]
    official_src: str
    state: dict
    notes: list[str] = field(default_factory=list)
    collector: list[PkgReport] = field(default_factory=list)
    seen: set[str] = field(default_factory=set)


_DIFF_MAX = 1_000_000  # bytes; larger changed files are hashed but not diffed


def resolve_names(names: list[str], env: Env) -> tuple[list[str], list[str]]:
    """Map user-supplied names to exact AUR names; return (resolved, failures)."""
    try:
        info = AUR.info(names)
    except HttpError as e:
        env.notes.append(f"cannot reach AUR metadata ({e}) - nothing checked")
        return [], list(names)
    resolved: list[str] = []
    failures: list[str] = []
    missing = [n for n in names if n not in info]
    for n in missing:
        try:
            hits = AUR.search(n)
        except HttpError:
            hits = []
        exact = [h for h in hits if h.get("Name") == n]
        if exact:
            AUR.info([n])
            resolved.append(n)
        else:
            close = ", ".join(h.get("Name", "?") for h in hits[:5]) or "none"
            env.notes.append(f"no AUR package named {n!r} (closest matches: {close})")
            failures.append(n)
    for n in names:
        if n in info:
            resolved.append(n)
    # de-dup, keep order
    out, seen = [], set()
    for n in resolved:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out, failures


def vet_many(names: list[str], opts: Opts, env: Env) -> list[PkgReport]:
    try:
        info = AUR.info(names)
    except HttpError as e:
        env.notes.append(f"cannot fetch metadata for vet pass: {e}")
        return []
    for n in names:
        rec = info.get(n)
        if not rec:
            report = PkgReport(
                name=n, verdict=Verdict.ERROR,
                notes=["no metadata returned by AUR for this name"],
            )
            env.collector.append(report)
            continue
        env.seen.add(n)
        vet_one(n, rec, opts, env, depth=0)
    return list(env.collector)


def vet_one(name: str, info: dict, opts: Opts, env: Env,
            depth: int = 0) -> PkgReport:
    findings: list[Finding] = []
    notes: list[str] = []
    report = PkgReport(name=name, info=info)
    env.collector.append(report)

    # 1. known-bad lists (exact campaign matches)
    for camp in env.bad.find(name):
        findings.append(Finding(
            "known-badlist", Severity.BLOCK,
            f"package is listed as compromised in known attack campaign {camp!r} "
            f"- do NOT install",
            "aur-malware-check",
        ))
    if depth > 0:
        notes.append(f"vetted as AUR dependency (depth {depth})")
    if env.bad.degraded:
        notes.append("known-bad lists partially unavailable (degraded) - list check less reliable")

    # 2. current content (the only thing that is ever judged)
    try:
        raw_files = AUR.snapshot(name)
    except HttpError as e:
        report.notes.append(f"could not fetch package content: {e}")
        report.findings = findings
        # A known-bad-list hit dominates a fetch failure: the package is
        # known-compromised whether or not we could read the current state.
        report.verdict = (Verdict.REJECT
                          if any(f.severity == Severity.BLOCK for f in findings)
                          else Verdict.ERROR)
        return report
    files = {p: d.decode("utf-8", errors="replace") for p, d in raw_files.items()}
    # One history fetch per package, reused for: head sha, cleared-state
    # diff context, new-committer detection, and the --clear committer set.
    # Keeping this at a single GitHub call per package is what lets a large
    # --watch list stay under the unauthenticated 60/hour API cap.
    commits: list | None = None
    try:
        commits = AUR.commits(name, per_page=50)
    except HttpError as e:
        notes.append(f"mirror history unavailable for {name!r}: {e}")
    report.git_sha = commits[0].sha if commits else ""

    if "PKGBUILD" not in files:
        report.verdict = Verdict.ERROR
        report.notes.append("snapshot contains no PKGBUILD - cannot vet")
        report.findings = findings
        return report
    pkg = pb.parse_pkgbuild(files["PKGBUILD"])

    install_field = pb.as_str(pkg, "install")
    install_paths = {
        p for p in files
        if (install_field and p == install_field) or p.endswith(".install")
    }

    ctx = rules.Ctx(
        name=name, pkg=pkg, info=info, files=files, install_paths=install_paths,
        official_names=env.official, npm_badlist=env.bad.all_npm_names(),
    )
    findings.extend(rules.run_all(ctx))

    # 3. dependency graph (the silent vector)
    dep_entries: list[dict] = []
    try:
        nodes, all_info, dep_truncated = depsmod.build_graph(name, info, env.official)
        if dep_truncated:
            notes.append(
                f"dependency graph truncated at {depsmod.MAX_DEPS} distinct "
                "dependencies - manual review of the full dependency list advised"
            )
    except HttpError as e:
        notes.append(f"dependency resolution degraded: {e}")
        nodes = []
    for node in nodes:
        entry = {"name": node.name, "kind": node.kind, "note": None}
        camp_hits = env.bad.find(node.name)
        for camp in camp_hits:
            findings.append(Finding(
                "bad-dependency", Severity.BLOCK,
                f"AUR dependency {node.name!r} is listed in known attack campaign "
                f"{camp!r} - installing this package would install it too",
                "dependencies",
            ))
        if camp_hits:
            entry["note"] = f"ON KNOWN-BAD LIST ({camp_hits[0]})"
        elif node.kind == "unknown":
            entry["note"] = "not resolvable via AUR - verify manually"
        else:
            lite = []
            if not node.info.get("Maintainer"):
                lite.append("orphaned")
            if node.info.get("OutOfDate"):
                lite.append("out-of-date")
            if lite:
                entry["note"] = ", ".join(lite)

        if opts.deep and node.kind == "aur" and node.info and depth < opts.max_depth \
                and node.name not in env.seen:
            child = vet_one(node.name, node.info, opts, env, depth=depth + 1)
            env.seen.add(node.name)
            dep_entries.append(entry)
            worst = child.verdict
            if worst == Verdict.REJECT:
                findings.append(Finding(
                    "deep-dependency", Severity.BLOCK,
                    f"dependency {node.name!r} is itself rejected - see its findings below",
                    "dependencies",
                ))
            elif worst == Verdict.REVIEW:
                findings.append(Finding(
                    "deep-dependency", Severity.WARN,
                    f"dependency {node.name!r} has warnings - inspect its findings below",
                    "dependencies",
                ))
            continue
        dep_entries.append(entry)

    report.deps = dep_entries

    # 4. cleared-state comparison (update policy)
    cleared = statemod.get_cleared(env.state, name)
    if cleared:
        _compare_cleared(report, name, raw_files, cleared, opts, notes,
                         findings, commits)

    report.findings = findings
    report.notes = notes
    report.verdict = finding_verdict(findings)

    # 5. optional: record as cleared
    if opts.clear:
        committers: list[str] = []
        for c in (commits or []):
            if c.author not in committers:
                committers.append(c.author)
        statemod.mark_cleared(
            env.state, name, report.git_sha, raw_files, report.verdict.label,
            extra={"committers": committers},
        )
    return report


def _compare_cleared(report: PkgReport, name: str, raw_files: dict[str, bytes],
                     cleared: dict, opts: Opts, notes: list[str],
                     findings: list[Finding], commits: list | None) -> None:
    if not cleared.get("git_sha"):
        notes.append("cleared state has no git sha - only file hashes compared")
    changed = statemod.changed_files(cleared, raw_files)
    report.changed_files = changed
    if not changed:
        return

    if cleared.get("git_sha") and commits is not None:
        since = str(cleared.get("cleared_at", ""))[:10]
        history = [c for c in commits if c.date[:10] > since]
        report.new_commits = [f"{c.sha[:10]} {c.author} ({c.date[:10]}): {c.message}"
                              for c in history]
        known = set(cleared.get("committers", []))
        if known:
            new_authors = {c.author for c in history} - known
            if new_authors:
                findings.append(Finding(
                    "new-committer", Severity.WARN,
                    f"new committer(s) since cleared: {', '.join(sorted(new_authors))} - "
                    "who committed is part of the trust decision",
                    "history",
                ))

    # unified diffs of changed files
    if opts.show_diff:
        for path in changed:
            cur = raw_files.get(path)
            if cur is None:
                continue
            old = None
            if cleared.get("git_sha"):
                try:
                    old = AUR.file_at(name, cleared["git_sha"], path)
                except HttpError as e:
                    notes.append(f"cannot fetch old revision of {path}: {e}")
            # difflib is quadratic-ish on large inputs; don't feed it a
            # megabyte payload. Hashes already prove the file changed.
            if len(cur) > _DIFF_MAX or (old is not None and len(old) > _DIFF_MAX):
                notes.append(
                    f"{path} changed and is too large to diff inline "
                    f"(>{_DIFF_MAX} bytes) - inspect it manually"
                )
                continue
            old_text = (old or b"<file did not exist>").decode("utf-8", errors="replace")
            cur_text = cur.decode("utf-8", errors="replace")
            diff = difflib.unified_diff(
                old_text.splitlines(), cur_text.splitlines(),
                fromfile=f"{path} (cleared)", tofile=f"{path} (current)",
                lineterm="", n=3,
            )
            report.file_diffs[path] = "\n".join(diff)

