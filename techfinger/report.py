#!/usr/bin/env python3
"""
Reporting for the fingerprint module.

Two outputs, both easy to read and easy to extend:

  render_console(fp)   coloured terminal block, matching subhunter's look
  build_json(fps)      structured dict for techfinger.json
  render_text(fps)     plain, delimited text report (techfinger.txt), the same
                       one-block-per-host shape as takeover_check.py

The console renderer degrades to no-colour automatically via the C palette
passed in, so this module stays decoupled from subhunter's globals.

Author : Savaid Khan
License: MIT
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .models import HostFingerprint, Technology

__version__ = "1.0.0"


# --------------------------------------------------------------------------- #
# Colour shim - a no-op palette so this module works standalone too.
# --------------------------------------------------------------------------- #


class _Plain:
    RESET = BOLD = DIM = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = ""


def _sev_colour(sev: str, C) -> str:
    return {
        "CRITICAL": C.RED,
        "HIGH": C.RED,
        "MEDIUM": C.YELLOW,
        "LOW": C.CYAN,
    }.get(sev, C.DIM)


# --------------------------------------------------------------------------- #
# Console (human, live)
# --------------------------------------------------------------------------- #


def render_console(fp: HostFingerprint, C=None, out=print) -> None:
    C = C or _Plain
    header = f"{fp.host}"
    if fp.url:
        header = fp.url
    out(f"\n{C.BOLD}{C.CYAN}>> {header}{C.RESET}")

    if fp.error:
        out(f"    {C.RED}collection failed: {fp.error}{C.RESET}")
        return

    # Security-header grade headline.
    sh = fp.security_headers or {}
    grade = sh.get("grade", "?")
    gcol = {"A": C.GREEN, "B": C.GREEN, "C": C.YELLOW, "D": C.YELLOW}.get(grade, C.RED)
    missing = sh.get("missing", [])
    out(f"    security headers: {gcol}{C.BOLD}{grade}{C.RESET}"
        f"  {C.DIM}({len(sh.get('present', {}))} present, {len(missing)} missing){C.RESET}")
    if sh.get("info_leaks"):
        out(f"    {C.YELLOW}info leaks:{C.RESET} {', '.join(sh['info_leaks'])}")

    techs = sorted(fp.technologies, key=lambda t: (t.category, t.name.lower()))
    if not techs:
        out(f"    {C.DIM}no technologies fingerprinted{C.RESET}")
        return

    for t in techs:
        ver = f" {C.BOLD}{t.version}{C.RESET}" if t.version else ""
        conf = f"{C.DIM}{t.confidence}%{C.RESET}"
        line = f"    [{C.CYAN}{t.category}{C.RESET}] {C.BOLD}{t.name}{C.RESET}{ver}  {conf}"
        out(line)

        # Worst CVE headline for this tech.
        if t.vulnerabilities:
            worst = t.vulnerabilities[0]
            scol = _sev_colour(worst.severity, C)
            flags = []
            if any(v.has_public_exploit for v in t.vulnerabilities):
                flags.append("exploit")
            if any(v.has_metasploit_module for v in t.vulnerabilities):
                flags.append("metasploit")
            flag_s = f" {C.RED}[{'/'.join(flags)}]{C.RESET}" if flags else ""
            out(f"        {scol}{len(t.vulnerabilities)} CVE(s), "
                f"top {worst.cve_id} CVSS {worst.cvss_score} {worst.severity}{C.RESET}{flag_s}")
        if t.end_of_life:
            out(f"        {C.RED}END-OF-LIFE{C.RESET} {C.DIM}{t.eol_detail}{C.RESET}")
        if t.recommended_version:
            out(f"        {C.GREEN}recommend:{C.RESET} {t.recommended_version}")


# --------------------------------------------------------------------------- #
# JSON
# --------------------------------------------------------------------------- #


def build_json(fps: list[HostFingerprint], domain: str = "") -> dict:
    total_tech = sum(len(f.technologies) for f in fps)
    total_cves = sum(len(t.vulnerabilities) for f in fps for t in f.technologies)
    eol = sum(1 for f in fps for t in f.technologies if t.end_of_life)
    exploitable = sum(
        1 for f in fps for t in f.technologies
        for v in t.vulnerabilities if v.has_public_exploit
    )
    return {
        "module": "techfinger",
        "version": __version__,
        "generated": datetime.now(timezone.utc).isoformat(),
        "domain": domain,
        "summary": {
            "hosts": len(fps),
            "technologies": total_tech,
            "cves": total_cves,
            "eol_technologies": eol,
            "exploitable_cves": exploitable,
        },
        "hosts": [f.to_dict() for f in fps],
    }


def write_json(fps: list[HostFingerprint], path, domain: str = "") -> None:
    from pathlib import Path
    Path(path).write_text(json.dumps(build_json(fps, domain), indent=2), encoding="utf-8")


# --------------------------------------------------------------------------- #
# Plain text (one block per host, takeover_check.py style)
# --------------------------------------------------------------------------- #

_SEP = "=" * 60


def render_text(fps: list[HostFingerprint], domain: str = "") -> str:
    lines: list[str] = []
    lines.append(f"# SubHunter techfinger report")
    lines.append(f"# generated: {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"# domain: {domain}")
    lines.append(f"# hosts: {len(fps)}")
    lines.append("")

    for fp in fps:
        lines.append(_SEP)
        lines.append(f"HOST: {fp.host}")
        lines.append(f"URL: {fp.url or '(none)'}")
        lines.append(f"STATUS: {fp.status_code if fp.status_code is not None else 'none'}")
        lines.append(_SEP)

        if fp.error:
            lines.append(f"ERROR: {fp.error}")
            lines.append("")
            continue

        sh = fp.security_headers or {}
        lines.append(f"SECURITY_HEADER_GRADE: {sh.get('grade', '?')}")
        if sh.get("missing"):
            lines.append(f"MISSING_SECURITY_HEADERS: {', '.join(sh['missing'])}")
        if sh.get("info_leaks"):
            lines.append("INFO_LEAK_HEADERS:")
            for k, v in sh["info_leaks"].items():
                lines.append(f"  {k}: {v}")

        tls = fp.tls or {}
        if tls and not tls.get("error"):
            lines.append(f"TLS: {tls.get('tls_version', '?')} "
                         f"issuer={tls.get('issuer_org') or tls.get('issuer_cn', '?')} "
                         f"verified={tls.get('verified', '?')}")

        lines.append("")
        lines.append("TECHNOLOGIES:")
        techs = sorted(fp.technologies, key=lambda t: (t.category, t.name.lower()))
        if not techs:
            lines.append("  (none)")
        for t in techs:
            lines.append(_render_tech_text(t))
        lines.append("")

    return "\n".join(lines)


def _render_tech_text(t: Technology) -> str:
    b: list[str] = []
    ver = t.version or "unknown"
    b.append(f"  - {t.name}  [{t.category}]  version={ver}  confidence={t.confidence}%")

    # Evidence (Phase 1 provenance).
    for e in t.evidence[:6]:
        b.append(f"      evidence({e.technique}, {e.confidence}%): {e.detail}")
    if t.version_candidates:
        cand = ", ".join(f"{k}={v}" for k, v in t.version_candidates.items())
        b.append(f"      version_candidates: {cand}")

    # Phase 3.
    if t.end_of_life is not None:
        b.append(f"      end_of_life: {t.end_of_life}  ({t.eol_detail})")
    if t.recommended_version:
        b.append(f"      recommended_version: {t.recommended_version}")
    if t.intel_status and t.intel_status != "ok":
        b.append(f"      intel_status: {t.intel_status}")

    if t.vulnerabilities:
        b.append(f"      CVEs ({len(t.vulnerabilities)}):")
        for v in t.vulnerabilities:
            flags = []
            if v.has_public_exploit:
                flags.append("PUBLIC-EXPLOIT")
            if v.has_metasploit_module:
                flags.append("METASPLOIT")
            fs = ("  " + " ".join(flags)) if flags else ""
            b.append(f"        {v.cve_id}  CVSS={v.cvss_score}  {v.severity}{fs}")
    return "\n".join(b)
