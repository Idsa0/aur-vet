"""Verdicts and rendering (text + JSON)."""

from __future__ import annotations

import io
import json
import re
from dataclasses import dataclass, field
from enum import IntEnum

from .rules import Finding, Severity


# Server-derived strings (AUR metadata, mirror commit data, package file
# contents) are rendered into the user's terminal at the moment they need
# scrutiny most. Strip ANSI escape sequences and control characters so a
# hostile package cannot wipe the screen, inject fake text, or hide
# characters inside the very report it is being judged against.
_ANSI_RE = re.compile(
    r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)?|..?)")
_CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def scrub(s: str) -> str:
    return _CTRL_RE.sub("", _ANSI_RE.sub("", s))


class Verdict(IntEnum):
    CLEAN = 0
    REVIEW = 1
    REJECT = 2
    ERROR = 3

    @property
    def label(self) -> str:
        return {0: "clean", 1: "review", 2: "reject", 3: "error"}[self.value]


@dataclass
class PkgReport:
    name: str
    verdict: Verdict = Verdict.CLEAN
    findings: list[Finding] = field(default_factory=list)
    info: dict | None = None
    deps: list[dict] = field(default_factory=list)   # {name, kind, note?}
    notes: list[str] = field(default_factory=list)   # free-form notes (resolved name, ...)
    changed_files: list[str] = field(default_factory=list)
    new_commits: list[str] = field(default_factory=list)  # "sha author msg"
    file_diffs: dict[str, str] = field(default_factory=dict)  # path -> unified diff
    git_sha: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "verdict": self.verdict.label,
            "git_sha": self.git_sha,
            "info": {
                "maintainer": (self.info or {}).get("Maintainer"),
                "version": (self.info or {}).get("Version"),
                "last_modified": (self.info or {}).get("LastModified"),
                "votes": (self.info or {}).get("NumVotes"),
                "orphan": not (self.info or {}).get("Maintainer"),
            },
            "findings": [
                {"rule": f.rule, "severity": f.severity.label,
                 "detail": f.detail, "where": f.where}
                for f in self.findings
            ],
            "deps": self.deps,
            "notes": self.notes,
            "changed_files": self.changed_files,
            "new_commits": self.new_commits,
            "file_diffs": self.file_diffs if self.file_diffs else None,
        }


class Colorizer:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def c(self, code: str, s: str) -> str:
        return f"\x1b[{code}m{s}\x1b[0m" if self.enabled else s


SEV_COLOR = {
    Severity.BLOCK: "1;31",
    Severity.WARN: "1;33",
    Severity.INFO: "36",
}
VERDICT_COLOR = {
    Verdict.CLEAN: "1;32",
    Verdict.REVIEW: "1;33",
    Verdict.REJECT: "1;31",
    Verdict.ERROR: "1;37",
}


def render_text(reports: list[PkgReport], notes: list[str], color: bool = True,
                show_diff: bool = True) -> str:
    col = Colorizer(color)
    out = io.StringIO()
    w = out.write

    for note in notes:
        w(col.c("90", f"note: {note}\n"))

    for r in reports:
        badge = col.c(VERDICT_COLOR[r.verdict], f"[{r.verdict.label.upper()}]")
        meta = []
        if r.info:
            m = r.info.get("Maintainer") or "ORPHAN"
            meta.append(f"maintainer={m}")
            meta.append(f"version={r.info.get('Version', '?')}")
            meta.append(f"votes={r.info.get('NumVotes', 0)}")
        w(f"\n{badge} {col.c('1', r.name)}" + (col.c("90", "  (" + "  ".join(meta) + ")") if meta else ""))
        for n in r.notes:
            w(f"    {col.c('90', n)}")
        for f in r.findings:
            tag = col.c(SEV_COLOR[f.severity], f"[{f.severity.label:>5}]")
            where = col.c("90", f"  ({f.where})") if f.where else ""
            w(f"    {tag} {f.rule}: {f.detail}{where}\n")
        if r.deps:
            w(col.c("90", "    dependencies:"))
            for d in r.deps:
                note = f"  {col.c('90', d['note'])}" if d.get("note") else ""
                w(f"      - {d['name']} ({d['kind']}){note}\n")
        if r.new_commits:
            w(col.c("1;33", f"    {len(r.new_commits)} new commit(s) since cleared:\n"))
            for cline in r.new_commits[:20]:
                w(f"      {col.c('90', cline)}\n")
            if len(r.new_commits) > 20:
                w(f"      {col.c('90', f'... and {len(r.new_commits) - 20} more')}\n")
        if r.changed_files:
            w(col.c("1;33", f"    changed files since cleared: {', '.join(r.changed_files)}\n"))
            if show_diff:
                for path, diff in r.file_diffs.items():
                    w(col.c("1", f"    --- {path} ---\n"))
                    for dline in diff.splitlines():
                        if dline.startswith("+") or dline.startswith("-"):
                            dline = col.c("32" if dline.startswith("+") else "31", dline)
                        else:
                            dline = col.c("90", dline)
                        w(f"      {dline}\n")
        if not r.findings and not r.deps and not r.new_commits and not r.changed_files:
            w(f"    {col.c('90', 'no findings (heuristics only - see RUNBOOK.md)')}\n")

    w("\n")
    worst = max((r.verdict for r in reports), default=Verdict.CLEAN)
    summary: dict[Verdict, int] = {}
    for r in reports:
        summary[r.verdict] = summary.get(r.verdict, 0) + 1
    parts = [f"{v.label}: {n}"
             for v, n in sorted(summary.items(), key=lambda kv: kv[0].value)]
    w(col.c(VERDICT_COLOR[worst], "overall: " + worst.label.upper()) + "  (" + ", ".join(parts) + ")\n")
    # JSON output: json.dumps (ensure_ascii) escapes all control chars, so
    # no raw escapes reach the terminal. Text output: scrub at the boundary.
    return scrub(out.getvalue())


def render_json(reports: list[PkgReport], notes: list[str]) -> str:
    worst = max((r.verdict for r in reports), default=Verdict.CLEAN)
    return json.dumps(
        {"overall": worst.label, "notes": notes, "packages": [r.to_dict() for r in reports]},
        indent=2,
    ) + "\n"


def finding_verdict(findings: list[Finding]) -> Verdict:
    worst = max((f.severity for f in findings), default=Severity.INFO)
    if worst == Severity.BLOCK:
        return Verdict.REJECT
    if worst == Severity.WARN:
        return Verdict.REVIEW
    return Verdict.CLEAN
