#!/usr/bin/env python3
"""
Shared HTTP + on-disk cache for the intelligence sources.

Phase 3 hits public APIs (NVD, endoflife.date, exploit catalogs) that are rate
limited and sometimes slow. A simple JSON file cache keyed by URL means repeat
scans - and multiple hosts sharing the same technology - only pay the network
cost once. TTL keeps the data fresh enough to matter.

Everything degrades gracefully: a cache miss + network failure returns None, and
callers treat None as "unknown", exactly like crt.sh failures in subhunter.py.

Author : Savaid Khan
License: MIT
"""

from __future__ import annotations

import hashlib
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

_CACHE_TTL = 7 * 24 * 3600      # a week; CVE data doesn't change hourly
_UA = "SubHunter-techfinger/1.0 (+https://github.com/Savaid-Khan-Official/savaid-tools)"

# Sentinel: a certificate-verification failure worth one lenient retry.
_CERT_ERROR = "__cert_verify_failed__"


def _lenient_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _fetch(req: urllib.request.Request, timeout: float, ctx: ssl.SSLContext | None):
    """One HTTP attempt. Returns (raw_text|None, error). error may be _CERT_ERROR."""
    try:
        if ctx is not None:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return resp.read().decode("utf-8", errors="replace"), ""
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace"), ""
    except urllib.error.HTTPError as e:
        if e.code == 403:
            return None, "HTTP 403 (rate limited - set NVD_API_KEY for higher limits)"
        if e.code == 404:
            return None, "not found"
        return None, f"HTTP {e.code}"
    except urllib.error.URLError as e:
        reason = getattr(e, "reason", e)
        if isinstance(reason, ssl.SSLError) or "CERTIFICATE_VERIFY_FAILED" in str(reason):
            return None, _CERT_ERROR
        return None, f"network error: {reason}"
    except (TimeoutError, OSError) as e:
        return None, f"error: {e}"
    except Exception as e:  # noqa: BLE001
        return None, f"unexpected: {type(e).__name__}: {e}"


def cache_dir() -> Path:
    """Per-user cache directory, OS-appropriate. Created on first use."""
    env = os.environ.get("SUBHUNTER_CACHE_DIR")
    if env:
        base = Path(env)
    elif sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        base = base / "subhunter" / "cache"
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "subhunter"
    try:
        base.mkdir(parents=True, exist_ok=True)
    except OSError:
        # Fall back to a temp dir if the home dir isn't writable.
        import tempfile
        base = Path(tempfile.gettempdir()) / "subhunter_cache"
        try:
            base.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
    return base


def _cache_path(url: str) -> Path:
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:32]
    return cache_dir() / f"{digest}.json"


def _read_cache(url: str) -> dict | list | None:
    p = _cache_path(url)
    try:
        if not p.is_file():
            return None
        if time.time() - p.stat().st_mtime > _CACHE_TTL:
            return None
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _write_cache(url: str, data) -> None:
    try:
        _cache_path(url).write_text(json.dumps(data), encoding="utf-8")
    except (OSError, TypeError, ValueError):
        pass


def get_json(
    url: str,
    *,
    timeout: float = 15.0,
    headers: dict | None = None,
    use_cache: bool = True,
) -> tuple[object | None, str]:
    """GET a URL and parse JSON. Returns (data|None, error).

    Cache hits skip the network entirely. Network/parse failures return
    (None, reason) so callers can record why intel is unavailable.
    """
    if use_cache:
        cached = _read_cache(url)
        if cached is not None:
            return cached, ""

    req = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": "application/json"})
    for k, v in (headers or {}).items():
        req.add_header(k, v)

    raw, err = _fetch(req, timeout, ctx=None)
    if err == _CERT_ERROR:
        # These are well-known public API endpoints (NVD, endoflife.date, CISA).
        # On boxes whose trust store can't verify the chain - common on Windows
        # and behind intercepting proxies - retry once without verification so
        # the intelligence phase still works, consistent with the toolkit's
        # existing lenient-TLS stance.
        raw, err = _fetch(req, timeout, ctx=_lenient_ctx())
    if err:
        return None, err

    if not raw.strip():
        return None, "empty response"
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None, "non-JSON response"

    if use_cache:
        _write_cache(url, data)
    return data, ""
