#!/usr/bin/env python3
"""
Security-intelligence orchestration - Phase 3.

Ties the three intel sources together for one host:

  nvd.py       -> CVEs, CVSS, severity
  eol.py       -> End-of-Life status + latest-in-cycle (recommendation floor)
  exploits.py  -> public-exploit + Metasploit availability (CISA KEV + refs)

For each detected Technology that maps to a known product (fingerprints.CPE_MAP)
and has a version, we enrich in place. Technologies without a version still get
an EOL/CVE-history attempt; those without any mapping are marked
"no intelligence source" so the report is honest about coverage.

enrich_host() never raises - any source failure is captured as intel_status.

Author : Savaid Khan
License: MIT
"""

from __future__ import annotations

from ..fingerprints import CPE_MAP
from ..models import HostFingerprint, Technology
from . import eol as eol_mod
from . import exploits as exploit_mod
from . import nvd as nvd_mod


def enrich_host(fp: HostFingerprint, *, online: bool = True, timeout: float = 20.0) -> HostFingerprint:
    if not online:
        for tech in fp.technologies:
            tech.intel_status = "offline (intelligence lookup skipped)"
        return fp

    for tech in fp.technologies:
        try:
            _enrich_tech(tech, timeout=timeout)
        except Exception as e:  # noqa: BLE001 - one tech must not sink the host
            tech.intel_status = f"error: {type(e).__name__}: {e}"
    return fp


def _enrich_tech(tech: Technology, *, timeout: float) -> None:
    mapping = CPE_MAP.get(tech.name)
    if not mapping:
        tech.intel_status = "no intelligence source for this technology"
        return

    vendor = mapping.get("vendor", "")
    product = mapping.get("product", "")
    eol_slug = mapping.get("eol", "")

    statuses: list[str] = []

    # ---- EOL first: it also yields the recommended-version floor ---------- #
    eol_latest = None
    if eol_slug:
        is_eol, detail, latest = eol_mod.check_eol(eol_slug, tech.version, timeout=timeout)
        tech.end_of_life = is_eol
        tech.eol_detail = detail
        eol_latest = latest
    else:
        tech.eol_detail = "no EOL calendar for this product"

    # ---- CVEs ------------------------------------------------------------- #
    if vendor and product:
        vulns, err = nvd_mod.lookup_cves(vendor, product, tech.version, timeout=timeout)
        if err:
            statuses.append(f"CVE: {err}")
        tech.vulnerabilities = vulns

        # ---- Exploit / Metasploit annotation ---------------------------- #
        if vulns:
            try:
                exploit_mod.annotate_exploits(vulns, online=True)
            except Exception as e:  # noqa: BLE001
                statuses.append(f"exploit-check: {e}")
    else:
        statuses.append("CVE: no CPE mapping")

    # ---- Recommendation --------------------------------------------------- #
    rec = exploit_mod.recommend_version(tech.vulnerabilities, eol_latest, tech.version)
    if rec:
        tech.recommended_version = rec
    elif tech.end_of_life:
        tech.recommended_version = "upgrade to a supported release (current is EOL)"

    tech.intel_status = "; ".join(statuses) if statuses else "ok"
