#!/usr/bin/env python3
"""
CVE lookup via the NVD 2.0 API.

Given a technology's (vendor, product, version) we build a CPE 2.3 string and
ask NVD for matching CVEs, then extract CVE ID, CVSS score/vector, severity and
description. Works keyless (NVD allows anonymous access at a low rate); if the
env var NVD_API_KEY is set we send it for the higher rate limit.

Results are cached to disk (cache.py), so a technology shared by many hosts is
fetched once. No key, no network, or a rate-limit 403 all degrade to "unknown".

Reference: https://nvd.nist.gov/developers/vulnerabilities

Author : Savaid Khan
License: MIT
"""

from __future__ import annotations

import os
import urllib.parse

from ..models import Vulnerability
from .cache import get_json

_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_MAX_CVES = 15          # keep reports readable; sorted worst-first


def _api_key_header() -> dict:
    key = os.environ.get("NVD_API_KEY", "").strip()
    return {"apiKey": key} if key else {}


def build_cpe(vendor: str, product: str, version: str | None) -> str:
    """Assemble a CPE 2.3 URI. Version '*' means any."""
    v = version if version else "*"
    # CPE forbids spaces; NVD expects lower-case vendor/product.
    vendor = vendor.strip().lower().replace(" ", "_")
    product = product.strip().lower().replace(" ", "_")
    return f"cpe:2.3:a:{vendor}:{product}:{v}:*:*:*:*:*:*:*"


def lookup_cves(
    vendor: str,
    product: str,
    version: str | None,
    *,
    timeout: float = 20.0,
) -> tuple[list[Vulnerability], str]:
    """Return (vulnerabilities, status). status '' means success."""
    cpe = build_cpe(vendor, product, version)

    if version:
        # cpeName matches this exact version's CVEs.
        url = f"{_NVD_BASE}?cpeName={urllib.parse.quote(cpe)}"
    else:
        # No version - use a virtual match on the product to at least surface
        # that the product has a CVE history.
        url = f"{_NVD_BASE}?virtualMatchString={urllib.parse.quote(cpe)}&resultsPerPage=20"

    data, err = get_json(url, timeout=timeout, headers=_api_key_header())
    if data is None:
        return [], err or "lookup failed"
    if not isinstance(data, dict):
        return [], "unexpected NVD response"

    vulns: list[Vulnerability] = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {}) if isinstance(item, dict) else {}
        v = _parse_cve(cve)
        if v:
            vulns.append(v)

    vulns.sort(key=lambda x: (x.cvss_score or 0.0), reverse=True)
    return vulns[:_MAX_CVES], ""


def _parse_cve(cve: dict) -> Vulnerability | None:
    cid = cve.get("id")
    if not cid:
        return None

    v = Vulnerability(cve_id=cid)
    v.published = (cve.get("published") or "")[:10]

    # English description.
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            v.description = d.get("value", "")
            break

    # CVSS: prefer v3.1 > v3.0 > v2.
    metrics = cve.get("metrics", {}) or {}
    score, sev, vector = _best_cvss(metrics)
    v.cvss_score = score
    v.severity = sev
    v.cvss_vector = vector

    # References - useful for the analyst, also mined for exploit hints.
    refs = []
    for r in cve.get("references", []):
        u = r.get("url")
        if u:
            refs.append(u)
    v.references = refs

    return v


def _best_cvss(metrics: dict) -> tuple[float | None, str, str]:
    for key in ("cvssMetricV31", "cvssMetricV30"):
        arr = metrics.get(key)
        if arr:
            data = arr[0].get("cvssData", {})
            score = data.get("baseScore")
            sev = data.get("baseSeverity", "") or _severity_from_score(score)
            return score, sev.upper() if sev else "UNKNOWN", data.get("vectorString", "")
    arr = metrics.get("cvssMetricV2")
    if arr:
        data = arr[0].get("cvssData", {})
        score = data.get("baseScore")
        sev = arr[0].get("baseSeverity", "") or _severity_from_score(score)
        return score, sev.upper() if sev else "UNKNOWN", data.get("vectorString", "")
    return None, "UNKNOWN", ""


def _severity_from_score(score: float | None) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"
