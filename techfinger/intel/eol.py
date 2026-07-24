#!/usr/bin/env python3
"""
End-of-Life detection via endoflife.date.

endoflife.date publishes machine-readable EOL calendars for hundreds of
products. Given a product slug (from fingerprints.CPE_MAP) and a version, we
find the matching release cycle and report whether it is past EOL, plus the
latest release in that cycle as a "recommended version" hint.

Cached and graceful: no slug, no network, or an unknown product all return
"unknown" rather than failing.

Reference: https://endoflife.date/docs/api

Author : Savaid Khan
License: MIT
"""

from __future__ import annotations

from datetime import date, datetime

from .cache import get_json

_BASE = "https://endoflife.date/api"


def check_eol(
    product_slug: str,
    version: str | None,
    *,
    timeout: float = 15.0,
) -> tuple[bool | None, str, str | None]:
    """Return (is_eol, detail, latest_in_cycle).

    is_eol is None when it cannot be determined.
    latest_in_cycle is a recommended-version hint (latest patch of the cycle).
    """
    if not product_slug:
        return None, "no EOL data source for this product", None

    url = f"{_BASE}/{product_slug}.json"
    data, err = get_json(url, timeout=timeout)
    if data is None:
        return None, f"EOL lookup unavailable: {err}", None
    if not isinstance(data, list):
        return None, "unexpected EOL response", None

    if not version:
        # Without a version we can still say whether the product *has* EOL'd
        # cycles, but not this host's status.
        return None, "version unknown - cannot determine EOL", None

    cycle = _match_cycle(data, version)
    if cycle is None:
        return None, f"version {version} not found in EOL calendar", None

    eol_field = cycle.get("eol")
    latest = cycle.get("latest")
    cycle_name = cycle.get("cycle", "")

    is_eol = _interpret_eol(eol_field)
    if is_eol is None:
        detail = f"cycle {cycle_name}: EOL status undetermined"
    elif is_eol:
        detail = f"cycle {cycle_name} reached EOL ({eol_field})"
    else:
        detail = f"cycle {cycle_name} supported (EOL: {eol_field})"

    return is_eol, detail, latest


def _match_cycle(cycles: list, version: str) -> dict | None:
    """Find the release cycle a version belongs to.

    endoflife cycles are labelled by their major(.minor) prefix, e.g. "1.18".
    Match the longest cycle label that prefixes the version.
    """
    best = None
    best_len = -1
    for c in cycles:
        if not isinstance(c, dict):
            continue
        cyc = str(c.get("cycle", ""))
        if version == cyc or version.startswith(cyc + "."):
            if len(cyc) > best_len:
                best, best_len = c, len(cyc)
    # Fall back to major-only match if nothing prefixed cleanly.
    if best is None:
        major = version.split(".")[0]
        for c in cycles:
            if isinstance(c, dict) and str(c.get("cycle", "")) == major:
                return c
    return best


def _interpret_eol(eol_field) -> bool | None:
    """eol may be a bool or an ISO date string."""
    if isinstance(eol_field, bool):
        return eol_field
    if isinstance(eol_field, str):
        try:
            eol_date = datetime.strptime(eol_field, "%Y-%m-%d").date()
        except ValueError:
            return None
        return eol_date <= date.today()
    return None
