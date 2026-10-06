"""Tiny HTTP GET helper with an on-disk ETag cache.

Standard library only. All fetches are plain GETs over http/https only;
nothing here writes outside the cache directory.

Security posture (this tool judges install safety, so its own input
channel is part of the trust boundary):

- TLS is verified (stdlib default context); a spoofed endpoint fails the
  certificate check before any body is trusted.
- **Redirects are policy-checked**: same host only, https never downgrades
  to http, max 5 hops. A hijacked/dirty endpoint that redirects elsewhere
  is a hard error, not a silent follow (cross-host follow would blur the
  "content came from X" guarantee, and downgrade would allow MITM reads).
- Only http/https schemes are accepted (no file:// etc., e.g. if a
  third-party campaign index ever carried a weird refresh_url).
- Response bodies are capped (``MAX_RESPONSE_BYTES``) and bounded by a
  total read deadline, so a hostile endpoint cannot stream unbounded data
  into memory.
- Policy failures (scheme, redirect) are *final*: no retries, no silent
  stale-cache fallback. Something redirecting us across hosts is exactly
  the sort of incident the tool exists to warn about, and serving a cached
  copy instead would hide it.
"""

from __future__ import annotations

import hashlib
import os
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

USER_AGENT = "aurvet/0.1 (+AUR pre-install vetting tool; stdlib urllib)"
DEFAULT_TIMEOUT = 30.0
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
_READ_CHUNK = 1024 * 1024
_TOTAL_TIME_FACTOR = 6  # total read budget = timeout * factor (slow-drip guard)


class HttpError(RuntimeError):
    """Network or HTTP-level failure.

    ``status`` is the HTTP code when known. ``final=True`` marks policy
    failures (scheme, redirect policy): no retry, no stale-cache fallback.
    """

    def __init__(self, msg: str, status: int | None = None, final: bool = False):
        super().__init__(msg)
        self.status = status
        self.final = final


class _StrictRedirectHandler(HTTPRedirectHandler):
    """urllib follows redirects; we only allow same-host, no downgrade."""

    max_repeats = 5

    def _validated(self, req, fp, code, msg, headers):
        loc = None
        for k, v in headers.items():
            if k.lower() in ("location", "uri", "url") and v:
                loc = v
                break
        if not loc:
            raise HttpError(
                f"redirect ({code}) without Location for {req.full_url}",
                status=code, final=True)
        old = urlsplit(req.full_url)
        new = urlsplit(loc)
        if new.scheme not in ("http", "https"):
            # also catches relative Locations (scheme == "")
            raise HttpError(
                f"redirect to disallowed scheme {new.scheme!r}: {loc}",
                status=code, final=True)
        if new.netloc.lower() != old.netloc.lower():
            raise HttpError(
                f"cross-host redirect: {old.netloc} -> {new.netloc}",
                status=code, final=True)
        if old.scheme == "https" and new.scheme == "http":
            raise HttpError(
                f"TLS downgrade via redirect: {loc}", status=code, final=True)
        return super().http_error_302(req, fp, code, msg, headers)

    http_error_301 = _validated
    http_error_302 = _validated
    http_error_303 = _validated
    http_error_307 = _validated


_OPENER = None  # built lazily: proxy env is read at first use, not import


def _opener():
    global _OPENER
    if _OPENER is None:
        _OPENER = build_opener(_StrictRedirectHandler())
    return _OPENER


def cache_dir() -> str:
    base = os.environ.get("XDG_CACHE_HOME", os.path.expanduser("~/.cache"))
    d = os.path.join(base, "aurvet")
    os.makedirs(d, exist_ok=True)
    return d


def _key(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()[:32]


def _load_cache(cpath: str) -> bytes | None:
    try:
        with open(cpath, "rb") as f:
            return f.read()
    except OSError:
        return None


def _read_meta(cpath: str) -> tuple[str, float]:
    """Return (etag, timestamp) for a cache entry."""
    try:
        with open(cpath + ".meta") as f:
            lines = f.read().splitlines()
    except OSError:
        return "", 0.0
    etag = lines[0] if lines and lines[0] else ""
    ts = float(lines[1]) if len(lines) > 1 and lines[1] else 0.0
    return etag, ts


def _write_cache(cpath: str, data: bytes, etag: str | None) -> None:
    tmp = cpath + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, cpath)
    with open(cpath + ".meta", "w") as f:
        f.write((etag or "") + "\n" + str(time.time()))


def _attempt(url: str, headers: dict, timeout: float) -> tuple[dict, bytes]:
    """One GET attempt. Returns (response_headers, body).

    Raises HttpError for HTTP-level errors (incl. status>=400 and the
    total-time budget), and (URLError, TimeoutError, OSError) subclasses
    for transport errors.
    """
    deadline = time.monotonic() + timeout * _TOTAL_TIME_FACTOR
    with _opener().open(Request(url, headers=headers), timeout=timeout) as r:
        status = r.status
        if status >= 500:
            raise HttpError(f"HTTP {status} for {url}: {getattr(r, 'reason', '?')}",
                            status=status)
        if not (200 <= status < 300):
            raise HttpError(f"unexpected HTTP {status} for {url}", status=status)
        chunks: list[bytes] = []
        total = 0
        while True:
            if time.monotonic() > deadline:
                raise HttpError(
                    f"total read time budget exceeded for {url} "
                    f"({timeout * _TOTAL_TIME_FACTOR:.0f}s)")
            chunk = r.read(_READ_CHUNK)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_RESPONSE_BYTES:
                raise HttpError(
                    f"response for {url} exceeds {MAX_RESPONSE_BYTES} byte cap")
            chunks.append(chunk)
        return dict(r.headers.items()), b"".join(chunks)


def fetch(
    url: str,
    *,
    use_cache: bool = True,
    max_age: float = 3600.0,
    timeout: float = DEFAULT_TIMEOUT,
    retries: int = 3,
) -> bytes:
    """GET a URL, returning body bytes.

    Caching policy:
      - A cache entry younger than ``max_age`` is served without any request.
      - Otherwise a conditional request is made (If-None-Match when we have an
        Etag); 304 reuses the cache, 200 replaces it.
      - Transport errors and HTTP 5xx are retried (``retries`` times) with
        backoff; 4xx final.
      - When retries are exhausted, a stale cache entry (if any) is served so
        the tool degrades gracefully rather than erroring.
      - Policy failures (scheme / redirect policy) abort immediately:
        no retry, no stale-cache fallback (see module docstring).

    ``use_cache=False`` disables reading the cache (the fresh response is
    still written to it).
    """
    scheme = urlsplit(url).scheme.lower()
    if scheme not in ("http", "https"):
        raise HttpError(f"disallowed URL scheme {scheme!r} for {url!r}",
                        final=True)

    cpath = os.path.join(cache_dir(), _key(url))
    etag, ts = _read_meta(cpath)
    now = time.time()

    if use_cache and ts and (now - ts) < max_age:
        cached = _load_cache(cpath)
        if cached is not None:
            return cached

    headers = {"User-Agent": USER_AGENT}
    if etag:
        headers["If-None-Match"] = etag
    no_conditional = False

    last: HttpError | None = None
    for attempt in range(retries + 1):
        try:
            rh, data = _attempt(url, headers, timeout)
            _write_cache(cpath, data, rh.get("ETag"))
            return data
        except HTTPError as e:
            if e.code == 304:
                cached = _load_cache(cpath)
                if cached is not None:
                    _write_cache(cpath, cached, e.headers.get("ETag") or etag)
                    return cached
                # 304 with an empty cache: refetch unconditionally once.
                if not no_conditional:
                    no_conditional = True
                    headers = {k: v for k, v in headers.items()
                               if k != "If-None-Match"}
                    continue
                last = HttpError(f"304 with empty cache for {url}", status=304)
                break
            last = HttpError(f"HTTP {e.code} for {url}: {e.reason}", status=e.code)
            if 300 <= e.code < 500:
                break  # non-redirectable 3xx and 4xx are not transient
        except (URLError, TimeoutError, OSError) as e:
            last = HttpError(f"fetch failed for {url}: {e}")
        except HttpError as e:
            if e.final:
                # Policy failure: surface it, do not paper over with cache.
                raise
            last = e  # HTTP 5xx surfaced from _attempt; retry
        if attempt < retries:
            time.sleep(1.5 * (2 ** attempt))

    cached = _load_cache(cpath) if use_cache else None
    if cached is not None:
        return cached
    raise last if last is not None else HttpError(f"fetch failed for {url}")
