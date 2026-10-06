"""AUR data access.

Content that is ever *judged* (PKGBUILD, install scripts) comes only from
aur.archlinux.org itself. The read-only GitHub mirror (archlinux/aur,
documented on the ArchWiki) is used solely for *history*: commit metadata
and fetching past file contents at a pinned SHA. History data never
influences the verdict of current content by itself.
"""

from __future__ import annotations

import io
import json
import re
import tarfile
from dataclasses import dataclass
from urllib.parse import quote

from .http import HttpError, fetch

AUR_HOST = "https://aur.archlinux.org"
GITHUB_API = "https://api.github.com/repos/archlinux/aur"
GITHUB_RAW = "https://raw.githubusercontent.com/archlinux/aur"

# RPC info requests are URI-length limited; 40 names per call is far below it.
_INFO_BATCH = 40


@dataclass(frozen=True)
class Commit:
    sha: str
    author: str
    date: str  # ISO 8601 (author date)
    message: str  # first line


class AUR:
    """Static-method client; all methods are class-level for easy mocking."""

    # ------------------------------------------------------------------ RPC

    @staticmethod
    def info(names: list[str]) -> dict[str, dict]:
        """Multiinfo for exact package names. Missing names are simply absent."""
        out: dict[str, dict] = {}
        for i in range(0, len(names), _INFO_BATCH):
            chunk = names[i : i + _INFO_BATCH]
            args = "&".join(f"arg[]={quote(n, safe='')}" for n in chunk)
            url = f"{AUR_HOST}/rpc/v5/info?{args}"
            payload = json.loads(fetch(url, max_age=300).decode("utf-8"))
            if payload.get("type") == "error":
                raise HttpError(str(payload.get("error", "AUR RPC error")))
            for rec in payload.get("results", []):
                out[rec["Name"]] = rec
        return out

    @staticmethod
    def search(keyword: str) -> list[dict]:
        url = f"{AUR_HOST}/rpc/v5/search/{quote(keyword, safe='')}?by=name-desc"
        payload = json.loads(fetch(url, use_cache=False).decode("utf-8"))
        if payload.get("type") == "error":
            raise HttpError(str(payload.get("error", "AUR RPC error")))
        return list(payload.get("results", []))

    # ----------------------------------------------------------- snapshots

    _TOPDIR = re.compile(r"/")

    @staticmethod
    def snapshot(name: str) -> dict[str, bytes]:
        """All files of a package base, path -> bytes, from aur.archlinux.org."""
        url = f"{AUR_HOST}/cgit/aur.git/snapshot/{quote(name, safe='')}.tar.gz"
        data = fetch(url, use_cache=False)
        files: dict[str, bytes] = {}
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            members = tf.getmembers()
            if not members:
                raise HttpError(f"empty snapshot for {name!r}")
            top = members[0].name.rstrip("/").split("/", 1)[0]
            prefix = top + "/"
            for m in members:
                if m.issym() or m.islnk() or m.isdev() or not m.isfile():
                    continue
                if not m.name.startswith(prefix):
                    continue
                rel = m.name[len(prefix):]
                if not rel or ".." in rel.split("/"):
                    continue
                f = tf.extractfile(m)
                if f is not None:
                    files[rel] = f.read()
        if not files:
            raise HttpError(f"snapshot for {name!r} contained no files")
        return files

    # -------------------------------------------------------- git history

    @staticmethod
    def commits(pkg: str, since_iso: str | None = None, per_page: int = 50) -> list[Commit]:
        """Recent commits on the package's mirror branch (newest first).

        ``since_iso`` bounds by *author date*, per the GitHub API; it is an
        approximation of "commits since this instant".
        """
        url = f"{GITHUB_API}/commits?sha={quote(pkg, safe='')}&per_page={per_page}"
        if since_iso:
            url += f"&since={quote(since_iso, safe='')}"
        payload = json.loads(fetch(url, use_cache=False).decode("utf-8"))
        if isinstance(payload, dict):
            # GitHub returns {"message": ...} on 404/rate-limit.
            msg = str(payload.get("message", "unknown error"))
            if "rate limit" in msg.lower():
                raise HttpError(f"GitHub API rate limit hit: {msg}")
            raise HttpError(f"no mirror history for {pkg!r}: {msg}")
        out: list[Commit] = []
        for c in payload:
            sha = c.get("sha", "")
            commit = c.get("commit", {})
            author = commit.get("author", {}) or {}
            message = (commit.get("message") or "").strip()
            out.append(
                Commit(
                    sha=sha,
                    author=author.get("name", "?"),
                    date=author.get("date", ""),
                    message=message.splitlines()[0] if message else "",
                )
            )
        return out

    @staticmethod
    def file_at(pkg: str, sha: str, path: str) -> bytes | None:
        """File content at a pinned SHA (immutable -> cache aggressively)."""
        url = f"{GITHUB_RAW}/{quote(sha, safe='')}/{quote(path, safe='/')}"
        try:
            return fetch(url, max_age=30 * 86400)
        except HttpError as e:
            if e.status == 404:
                return None
            raise
