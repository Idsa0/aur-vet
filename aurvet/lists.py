"""Known-bad package lists, sourced from aur-malware-check.

The campaign index (campaigns.json) and per-campaign package/npm lists are
fetched from the upstream repo; where a campaign declares a live
``refresh_url`` (e.g. the official Arch HedgeDoc), that list is fetched too
and unioned in. Network failure degrades to whatever is cached, and if
nothing at all can be loaded the caller proceeds with an empty (flagged)
list set - list matching can never be the *only* line of defense.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from .http import HttpError, fetch

_REPO_RAW = "https://raw.githubusercontent.com/lenucksi/aur-malware-check/master"
CAMPAIGNS_URL = f"{_REPO_RAW}/data/campaigns.json"
_DEFAULT_MAX_AGE = 3600.0


@dataclass
class Campaign:
    id: str
    display: str
    packages: set[str] = field(default_factory=set)
    npm_packages: set[str] = field(default_factory=set)
    refresh_url: str | None = None
    lists_loaded: int = 0


@dataclass
class BadLists:
    campaigns: list[Campaign]
    degraded: bool = False  # True when fewer lists loaded than expected

    def find(self, name: str) -> list[str]:
        """Display names of campaigns listing this AUR package."""
        name = name.strip().lower()
        return [
            c.display
            for c in self.campaigns
            if name in {p.lower() for p in c.packages}
        ]

    def find_npm(self, name: str) -> list[str]:
        name = name.strip().lower()
        return [
            c.display
            for c in self.campaigns
            if name in {p.lower() for p in c.npm_packages}
        ]

    def all_npm_names(self) -> set[str]:
        out: set[str] = set()
        for c in self.campaigns:
            out |= {p.lower() for p in c.npm_packages}
        return out


def _parse_names(text: str) -> set[str]:
    out: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("```"):
            continue
        if any(c.isspace() for c in line):
            continue  # not a bare package name (markdown prose, table rows, ...)
        out.add(line)
    return out


def _as_str_list(v) -> list[str]:
    """Tolerate malformed upstream JSON: only real string lists survive."""
    if isinstance(v, list):
        return [s for s in v if isinstance(s, str)]
    return []


def load(refresh: bool = True) -> BadLists:
    """Load all campaign lists. Never raises; see ``degraded``."""
    campaigns: list[Campaign] = []
    expected = 0
    loaded = 0
    max_age = _DEFAULT_MAX_AGE if refresh else float("inf")

    try:
        raw = json.loads(fetch(CAMPAIGNS_URL, max_age=max_age).decode("utf-8"))
    except (HttpError, ValueError):  # ValueError: malformed JSON upstream
        return BadLists(campaigns=[], degraded=True)

    campaigns_raw = raw.get("campaigns") if isinstance(raw, dict) else None
    if not isinstance(campaigns_raw, list):
        # malformed upstream index: degrade, do not crash
        return BadLists(campaigns=[], degraded=True)

    for entry in campaigns_raw:
        if not isinstance(entry, dict):
            continue
        cid = str(entry.get("id", "?"))
        display = str(entry.get("display", cid))
        refresh_url = entry.get("refresh_url")
        camp = Campaign(
            id=cid,
            display=display,
            refresh_url=refresh_url if isinstance(refresh_url, str) else None,
        )
        files: list[str] = []
        files += _as_str_list(entry.get("lists"))
        files += _as_str_list(entry.get("npm_lists"))
        expected += len(files)
        if camp.refresh_url:
            expected += 1

        for rel in _as_str_list(entry.get("lists")):
            try:
                names = _parse_names(fetch(f"{_REPO_RAW}/{rel}", max_age=max_age).decode("utf-8"))
                camp.packages |= names
                loaded += 1
            except HttpError:
                continue
        for rel in _as_str_list(entry.get("npm_lists")):
            try:
                names = _parse_names(fetch(f"{_REPO_RAW}/{rel}", max_age=max_age).decode("utf-8"))
                camp.npm_packages |= names
                loaded += 1
            except HttpError:
                continue
        if isinstance(entry.get("refresh_url"), str):
            try:
                names = _parse_names(fetch(entry["refresh_url"], max_age=max_age).decode("utf-8"))
                camp.packages |= names
                loaded += 1
            except HttpError:
                continue

        campaigns.append(camp)

    return BadLists(campaigns=campaigns, degraded=expected > 0 and loaded < expected)
