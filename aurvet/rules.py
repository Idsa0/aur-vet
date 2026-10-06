"""Static heuristic rules applied to a package's PKGBUILD + install scripts.

Rules map observable patterns to findings with a severity:
  INFO  - neutral context (orphan, VCS, install script exists)
  WARN  - needs a human look (review verdict)
  BLOCK - strong malware indicator (reject verdict)

Rules are heuristics, not proof. A BLOCK means "do not install this without
reading exactly this line by hand", not "this package is malware".
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import IntEnum

from . import pkgbuild as pb


class Severity(IntEnum):
    INFO = 0
    WARN = 1
    BLOCK = 2

    @property
    def label(self) -> str:
        return {0: "info", 1: "warn", 2: "block"}[self.value]


@dataclass
class Finding:
    rule: str
    severity: Severity
    detail: str
    where: str = ""  # file:line or key context


@dataclass
class Ctx:
    name: str
    pkg: dict[str, object]          # parsed PKGBUILD fields
    info: dict                      # AUR multiinfo record
    files: dict[str, str]           # all snapshot file texts (PKGBUILD, .install, ...)
    install_paths: set[str]         # which of the files are install scripts
    official_names: set[str]
    npm_badlist: set[str] = field(default_factory=set)


# ----------------------------------------------------------------- patterns

_PATH_SH = r"(?:/[\w.-]+)*([\w.-]+/)*(?:ba|z|k|da|fi)?sh(?![\w-])"  # bash/zsh/...
_PIPED_EXEC = re.compile(r"\|\s*(?:sudo\s+(?:-\S+\s+)*)?" + _PATH_SH)
_AND_EXEC = re.compile(
    r"(?:&&|\|\|)\s*(?:sudo\s+(?:-\S+\s+)*)?" + _PATH_SH + r"\s"
)
_DL = r"\b(?:curl|wget|fetch)\b"
_SHC_DL = re.compile(r"(?:ba|z|k|da|fi)?sh(?![\w-])\s+-[^\n]*\S[^\n]*" + _DL)
_EVAL_DL = re.compile(r"\beval\b[^\n]*" + _DL)
_B64_PIPE = re.compile(r"base64\s+(?:-d|--decode)\b[^\n|]*\|\s*\w*(?:ba|z|k)?sh\b")
_ECHO_B64 = re.compile(r"echo\s+[\"']?[\w+/]{120,}={0,2}[\"']?\s*\|\s*base64")
_LONG_B64 = re.compile(r"[\w+/]{300,}={0,2}")

_SUSPICIOUS_HOSTS = {
    "pastebin.com", "dpaste.org", "0x0.st", "ix.io", "sprunge.us", "sprunge.de",
    "transfer.sh", "file.io", "tmpfiles.org", "hastebin.com", "litterbox.catbox.moe",
    "catbox.moe", "bit.ly", "t.co", "is.gd", "tinyurl.com", "clck", "ow.ly",
    "ngrok.io", "ngrok-free.app",
}
_URL_HOST = re.compile(r"https?://([\w.-]+)")

_JS_PKG = re.compile(
    r"\b(?:npm\s+(?:i|install|add)\s+|bun\s+(?:add|install)\s+|yarn\s+add\s+|"
    r"pnpm\s+(?:add|install)\s+)"
    r"((?:-{1,2}[\w-]+\s+)*)"      # flags, e.g. -g --force
    r"([A-Za-z0-9@/._-]+)"         # the package spec
)

_ROOT_ACTS = [
    (re.compile(r"\bsystemctl\s+(enable|start|restart|reload|daemon-reload|preset)\b"),
     "service/persistence via systemctl {0}"),
    (re.compile(r"\bsystemd-sysv-install\b"), "systemd-sysv-install"),
    (re.compile(r"\bcrontab\b"), "crontab"),
    (re.compile(r"\b(useradd|usermod|groupadd|groupmod|visudo)\b"), "account modification via {0}"),
    (re.compile(r"(?:>>?|tee\s+-a?\s+)(?:[\"']?)/etc/"), "write to /etc/"),
    (re.compile(r"\b(?:sed|tee|install)\b[^\n]*(?:--|-D\s+)(?:[\"']?)/etc/"), "write to /etc/"),
    (re.compile(r"(?:>>?|tee\s+)(?:[^\n]*\s)?[\w~$./-]*\.(?:bashrc|zshrc|profile|bash_profile|zprofile)\b"),
     "write to shell rc file"),
    (re.compile(r"\bld\.so\.preload\b"), "ld.so.preload"),
    (re.compile(r"\bchmod\s+(?:\S+\s+)*(?:u|g|o|a)?\+s\b"), "setuid via chmod +s"),
    (re.compile(r"\bchmod\s+(?:[0-7]+,)*[4-7]\d{3}(?!\d)\b"), "setuid octal chmod (4-digit mode)"),
]

_FLOATING = re.compile(
    r"github\.com/[\w.-]+/[\w.-]+/(?:archive|tarball|zipball)/(?:refs/heads/)?(?:master|main|trunk|HEAD)\b"
    r"|/latest/"
    r"|codeload\.github\.com/[\w.-]+/[\w.-]+/[^\s\"']*(?:refs/heads/)?(?:master|main|trunk|HEAD)(?:\.|/|\?|$)"
)


def _source_entries(pkg: dict[str, object]) -> list[str]:
    return [s for s in pb.as_list(pkg, "source") if s and s != "SKIP"]


# Rules scan *commands*, not megabytes of blob data. A line beyond this is
# itself a warning; only its prefix is scanned.
_MAX_LINE = 16 * 1024


def _iter_lines(ctx: Ctx):
    """Yield (path, lineno, line, truncated) over all file texts, capping
    each line to ``_MAX_LINE`` characters so the per-line regexes stay
    bounded regardless of what a package ships."""
    for path, text in ctx.files.items():
        for lineno, line in enumerate(text.splitlines(), 1):
            if len(line) > _MAX_LINE:
                yield path, lineno, line[:_MAX_LINE], True
            else:
                yield path, lineno, line, False


def _vcs_exempt(entry: str) -> bool:
    url = entry.split("::", 1)[-1]
    if "$" in entry:  # templated / VCS-derived
        return True
    return url.startswith(("git+", "svn+", "bzr+", "hg+", "cvs+", "rsync+"))


# -------------------------------------------------------------------- rules

def rule_net_exec(ctx: Ctx) -> list[Finding]:
    out = []
    for path, lineno, line, _trunc in _iter_lines(ctx):
        if not re.search(_DL, line):
            continue
        if _PIPED_EXEC.search(line):
            detail = "downloads and pipes to a shell"
        elif _AND_EXEC.search(line):
            detail = "downloads a file then executes it as a shell script"
        elif _SHC_DL.search(line):
            detail = "shell -c invoked with downloaded content"
        elif _EVAL_DL.search(line):
            detail = "eval of downloaded content"
        else:
            continue
        out.append(Finding("net-exec", Severity.BLOCK,
                           f"{detail}: {line.strip()!r}", f"{path}:{lineno}"))
    return out


def rule_obfuscated(ctx: Ctx) -> list[Finding]:
    out = []
    for path, lineno, line, _trunc in _iter_lines(ctx):
        if _B64_PIPE.search(line):
            out.append(Finding("obfuscated-exec", Severity.BLOCK,
                               f"base64-decoded payload piped to shell: {line.strip()!r}",
                               f"{path}:{lineno}"))
        elif _ECHO_B64.search(line):
            out.append(Finding("obfuscated-exec", Severity.BLOCK,
                               f"echo of long base64 blob into base64: {line.strip()!r}",
                               f"{path}:{lineno}"))
        elif _LONG_B64.search(line):
            out.append(Finding("long-base64", Severity.WARN,
                               f"long base64-looking blob: {line.strip()[:80]!r}...",
                               f"{path}:{lineno}"))
    return out


def rule_suspicious_host(ctx: Ctx) -> list[Finding]:
    out = []
    seen: set[str] = set()
    for path, text in ctx.files.items():
        for host in _URL_HOST.findall(text):
            host = host.lower().rstrip(".")
            key = host
            if key in seen:
                continue
            if any(host == h or host.endswith("." + h) for h in _SUSPICIOUS_HOSTS):
                seen.add(key)
                out.append(Finding(
                    "suspicious-host", Severity.WARN,
                    f"references untrusted file-host/shortener domain {host!r}",
                    path,
                ))
    return out


def rule_insecure_source(ctx: Ctx) -> list[Finding]:
    out = []
    for src in _source_entries(ctx.pkg):
        if re.match(r"^(?:\S+::)?http://", src):
            out.append(Finding("insecure-source", Severity.WARN,
                               f"non-TLS source: {src!r}", "source"))
    return out


def rule_missing_hashes(ctx: Ctx) -> list[Finding]:
    urls = [s for s in _source_entries(ctx.pkg)
            if ("://" in s or "::" in s) and not _vcs_exempt(s)]
    sigs = [s for s in urls if re.search(r"\.(sig|asc)$", s)]
    need = len(urls) - len(sigs)
    hashes = pb.as_list(ctx.pkg, "sha256sums")
    out = []
    if need and not hashes:
        out.append(Finding("missing-hashes", Severity.WARN,
                           f"{need} source file(s) but no sha256sums() at all",
                           "sha256sums"))
    elif need and len(hashes) < need:
        out.append(Finding("missing-hashes", Severity.WARN,
                           f"{len(hashes)} hash(es) for {need} source file(s) - "
                           "checksums may be incomplete", "sha256sums"))
    return out


def rule_vcs_floating(ctx: Ctx) -> list[Finding]:
    out = []
    for src in _source_entries(ctx.pkg):
        if _FLOATING.search(src):
            out.append(Finding("vcs-floating", Severity.INFO,
                               f"source floats on a moving branch head: {src!r} - "
                               "pin a tag/commit or verify the version at build time",
                               "source"))
    return out


def rule_install_file(ctx: Ctx) -> list[Finding]:
    out = []
    for path in sorted(ctx.install_paths):
        out.append(Finding(
            "install-script", Severity.INFO,
            f"root install script present: {path} - read it before building",
            path,
        ))
    return out


def rule_root_acts(ctx: Ctx) -> list[Finding]:
    out = []
    for path, lineno, line, _trunc in _iter_lines(ctx):
        for pat, desc in _ROOT_ACTS:
            m = pat.search(line)
            if m:
                label = desc if "{0}" not in desc else desc.format(m.group(1))
                out.append(Finding("root-acts", Severity.WARN,
                                   f"{label}: {line.strip()!r}",
                                   f"{path}:{lineno}"))
                break  # one finding per line is enough
    return out


def rule_js_package(ctx: Ctx) -> list[Finding]:
    """Named package-manager installs inside build scripts.

    Generalized form of the 2026-06 vector (``npm install atomic-lockfile``):
    a *specific* JS package pulled at build time is either (a) on the known
    bad npm list -> BLOCK, or (b) not clearly part of the declared build ->
    WARN. Bare `npm install` (install-from-package.json) is not flagged.
    """
    out = []
    makedeps = {re.split(r"[<>!=]", d, maxsplit=1)[0].strip()
                for d in pb.as_list(ctx.pkg, "makedepends")}
    for path, lineno, line, _trunc in _iter_lines(ctx):
        for m in _JS_PKG.finditer(line):
            spec = m.group(2)
            # skip flags / flag values / local paths; package specs start
            # with a letter or @ (scope)
            if not re.match(r"^[A-Za-z@]", spec):
                continue
            base = spec.rsplit("/", 1)[-1]
            if base.lower() in {h.lower() for h in ctx.npm_badlist}:
                out.append(Finding(
                    "known-bad-npm", Severity.BLOCK,
                    f"build installs known-malicious JS package {spec!r}",
                    f"{path}:{lineno}",
                ))
            elif base not in makedeps and spec not in makedeps:
                out.append(Finding(
                    "js-build-dep", Severity.WARN,
                    f"build installs specific JS package {spec!r} not found in "
                    "makedepends - verify it is part of the build",
                    f"{path}:{lineno}",
                ))
    return out


def rule_shadow_official(ctx: Ctx) -> list[Finding]:
    out = []
    off = ctx.official_names
    if not off:
        return out
    name = ctx.name
    if name in off:
        out.append(Finding("shadow-official", Severity.WARN,
                           f"AUR package name equals official repository package "
                           f"{name!r} - explain why before installing", "pkgname"))
    for key, verb in (("provides", "provides"), ("conflicts", "conflicts with"),
                      ("replaces", "replaces")):
        for entry in pb.as_list(ctx.pkg, key):
            bare = re.split(r"[<>!=]", entry, maxsplit=1)[0].strip()
            if bare in off:
                out.append(Finding("shadow-official", Severity.WARN,
                                   f"{key}() {verb} official repository package {bare!r}",
                                   key))
    return out


def _lev1(a: str, b: str) -> bool:
    """True when edit distance between a and b is exactly 1."""
    if a == b:
        return False
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:
        diff = 0
        for ca, cb in zip(a, b):
            if ca != cb:
                diff += 1
            if diff > 1:
                return False
        return diff == 1
    if la > lb:
        a, b, la, lb = b, a, lb, la
    i = j = 0
    skipped = False
    while i < la and j < lb:
        if a[i] == b[j]:
            i += 1
            j += 1
        elif skipped:
            return False
        else:
            skipped = True
            j += 1
    return True


def rule_typosquat(ctx: Ctx) -> list[Finding]:
    out = []
    name = ctx.name.lower()
    for off in ctx.official_names:
        if len(off) < 5 or not _lev1(name, off.lower()):
            continue
        out.append(Finding(
            "typosquat", Severity.WARN,
            f"package name {name!r} is one edit away from official {off!r} - "
            "verify this is a distinct project, not a lookalike",
            "pkgname",
        ))
        if len(out) >= 3:
            break
    return out


def rule_orphan(ctx: Ctx) -> list[Finding]:
    if not ctx.info.get("Maintainer"):
        return [Finding("orphan", Severity.INFO,
                        "package has no maintainer (orphaned)", "maintainer")]
    return []


def rule_out_of_date(ctx: Ctx) -> list[Finding]:
    ood = ctx.info.get("OutOfDate")
    if ood:
        when = time.strftime("%Y-%m-%d", time.gmtime(ood))
        return [Finding("out-of-date", Severity.INFO,
                        f"flagged out-of-date since {when}", "meta")]
    return []


_RULES = [
    rule_net_exec,
    rule_obfuscated,
    rule_suspicious_host,
    rule_insecure_source,
    rule_missing_hashes,
    rule_vcs_floating,
    rule_install_file,
    rule_root_acts,
    rule_js_package,
    rule_shadow_official,
    rule_typosquat,
    rule_orphan,
    rule_out_of_date,
]


def run_all(ctx: Ctx) -> list[Finding]:
    findings: list[Finding] = []
    for rule in _RULES:
        findings.extend(rule(ctx))

    # Oversized lines: bounded-scan disclosure (one finding per file).
    truncated_files: set[str] = set()
    for path, _lineno, _line, trunc in _iter_lines(ctx):
        if trunc:
            truncated_files.add(path)
    for path in sorted(truncated_files):
        findings.append(Finding(
            "oversized-line", Severity.WARN,
            f"{path} contains a line longer than {_MAX_LINE // 1024} KiB; only "
            "its prefix was scanned - inspect the full line manually",
            path,
        ))

    order = {Severity.BLOCK: 0, Severity.WARN: 1, Severity.INFO: 2}
    findings.sort(key=lambda f: (order[f.severity], f.rule, f.where))
    return findings
