#!/usr/bin/env python3
"""
techfinger - Technology Fingerprinting & Security Intelligence for SubHunter.

A modular, stdlib-only extension that runs immediately after SubHunter's live
subdomain stage. For every live host it:

  Phase 1  fingerprints technologies (web server, framework, CMS, JS libs,
           CDN, WAF, TLS, security headers ...) with confidence + evidence,
  Phase 2  merges multi-technique version evidence into a best-guess version,
  Phase 3  enriches each (technology, version) with CVEs, CVSS, severity,
           EOL status, public-exploit and Metasploit availability, and a
           recommended fixed version.

Public API
----------
fingerprint_host(host, *, timeout, url=None, ...) -> HostFingerprint
    Fingerprint a single host (Phase 1 + Phase 2).

enrich(fp, *, online=True) -> HostFingerprint
    Add Phase 3 security intelligence to an already-fingerprinted host.

fingerprint_and_enrich(host, ...) -> HostFingerprint
    Convenience: Phase 1 + 2 + 3 in one call.

The whole package degrades gracefully: no network, no dig, no API key - it
still returns whatever it could determine and records why the rest is unknown.

Author : Savaid Khan
Version: 1.0.0
License: MIT
"""

from __future__ import annotations

from .models import (
    Confidence,
    Evidence,
    HostFingerprint,
    Technology,
    Vulnerability,
)

__author__ = "Savaid Khan"
__version__ = "1.0.0"

__all__ = [
    "Confidence",
    "Evidence",
    "HostFingerprint",
    "Technology",
    "Vulnerability",
    "fingerprint_host",
    "enrich",
    "fingerprint_and_enrich",
    "__version__",
]


def fingerprint_host(
    host: str,
    *,
    timeout: float = 10.0,
    url: str | None = None,
    insecure: bool = True,
) -> HostFingerprint:
    """Phase 1 + Phase 2 for a single host. Never raises."""
    # Imported lazily so importing the package is cheap and so a partially
    # broken install still exposes the data model.
    from .collect import collect_evidence
    from .engine import fingerprint
    from .versions import validate_versions

    ev = collect_evidence(host, timeout=timeout, url=url, insecure=insecure)
    fp = fingerprint(ev)
    validate_versions(fp)
    return fp


def enrich(fp: HostFingerprint, *, online: bool = True, timeout: float = 15.0) -> HostFingerprint:
    """Phase 3: attach CVE / EOL / exploit intelligence. Never raises."""
    from .intel import enrich_host

    return enrich_host(fp, online=online, timeout=timeout)


def fingerprint_and_enrich(
    host: str,
    *,
    timeout: float = 10.0,
    url: str | None = None,
    insecure: bool = True,
    online: bool = True,
) -> HostFingerprint:
    fp = fingerprint_host(host, timeout=timeout, url=url, insecure=insecure)
    if not fp.error:
        enrich(fp, online=online, timeout=timeout)
    return fp
