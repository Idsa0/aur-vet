"""A pragmatic PKGBUILD parser.

Parses top-level ``key = value`` assignments into a flat mapping:
arrays -> list[str], scalars -> str. It is deliberately not a bash parser:
function bodies (pkgver() etc.) are not needed and are tolerated as noise.
Only the well-known keys (pkgname, source, sha256sums, depends, makedepends,
provides, conflicts, replaces, install, options, url, validpgpkeys,
noextract) matter to the rule engine.
"""

from __future__ import annotations

import re

_KEY = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*", re.M)


def _scan_array(text: str, start: int) -> tuple[int, str]:
    """text[start] == '('. Return (end_index, body) for the balanced array."""
    depth = 0
    quote: str | None = None
    i = start
    n = len(text)
    while i < n:
        ch = text[i]
        if quote:
            if ch == quote and (i == start + 1 or text[i - 1] != "\\"):
                quote = None
        elif ch in "\"'":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i + 1, text[start + 1 : i]
        i += 1
    return n, text[start + 1 :]  # unbalanced; take the rest


def _split_array(body: str) -> list[str]:
    """Split array body into elements, honoring quotes and skipping comments."""
    elems: list[str] = []
    cur: list[str] = []
    quote: str | None = None
    i = 0
    n = len(body)
    while i < n:
        ch = body[i]
        if quote:
            cur.append(ch)
            if ch == quote and (i == 0 or body[i - 1] != "\\"):
                quote = None
            i += 1
            continue
        if ch in "\"'":
            # Start of a quoted chunk; keep everything until closing quote.
            quote = ch
            cur.append(ch)
            i += 1
            continue
        if ch == "#":
            # Comment to end of line.
            while i < n and body[i] != "\n":
                i += 1
            continue
        if ch.isspace():
            tok = "".join(cur).strip()
            if tok:
                elems.append(_unquote(tok))
            cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    tok = "".join(cur).strip()
    if tok:
        elems.append(_unquote(tok))
    return elems


def _unquote(tok: str) -> str:
    """Strip a surrounding matched pair of quotes, if any."""
    if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in "\"'":
        inner = tok[1:-1]
        # Only treat as quoted if no unmatched inner quote; otherwise keep raw.
        return inner
    return tok


def _strip_comment(value: str) -> str:
    quote: str | None = None
    for i, ch in enumerate(value):
        if quote:
            if ch == quote and (i == 0 or value[i - 1] != "\\"):
                quote = None
        elif ch in "\"'":
            quote = ch
        elif ch == "#":
            return value[:i].rstrip()
    return value.rstrip()


def parse_pkgbuild(text: str) -> dict[str, object]:
    fields: dict[str, object] = {}
    pos = 0
    n = len(text)
    while pos < n:
        m = _KEY.search(text, pos)
        if not m:
            break
        key = m.group(1)
        vstart = m.end()
        # Value must start on the same line.
        rest = text[vstart:]
        nl = rest.find("\n")
        first_line = rest[:nl] if nl != -1 else rest
        stripped = first_line.lstrip()
        if not stripped:
            pos += nl + 1 if nl != -1 else 1
            continue
        c = stripped[0]
        if c == "(":
            end, body = _scan_array(text, vstart + (len(first_line) - len(stripped)))
            fields[key] = _split_array(body)
            pos = end
        elif c in "\"'":
            raw = _strip_comment(first_line.strip())
            fields[key] = _unquote(raw) if raw and raw[0] in "\"'" else raw
            pos += nl + 1 if nl != -1 else 1
        else:
            fields[key] = _strip_comment(first_line.strip())
            pos += nl + 1 if nl != -1 else 1
    return fields


def as_str(fields: dict[str, object], key: str, default: str = "") -> str:
    v = fields.get(key, default)
    return v if isinstance(v, str) else default


def as_list(fields: dict[str, object], key: str) -> list[str]:
    v = fields.get(key, [])
    return list(v) if isinstance(v, list) else []
