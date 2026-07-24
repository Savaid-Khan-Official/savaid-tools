#!/usr/bin/env python3
"""
Fingerprint engine - Phase 1.

Pure logic: given a collected Evidence bundle, run every technique in the
fingerprint database and build a list of Technology objects, each carrying the
evidence and confidence that produced it. No network I/O happens here.

Techniques used per fingerprint rule:
  header          exact response-header value match
  any_header      match against the whole "Name: value" header line
  cookie          Set-Cookie name match
  body            HTML body match
  meta_generator  the <meta name="generator"> content
  script          any <script src="..."> URL

Multiple techniques hitting the same technology is the point: that corroboration
is what versions.py turns into a confident version in Phase 2.

Author : Savaid Khan
License: MIT
"""

from __future__ import annotations

import re

from .collect import Evidence
from .fingerprints import (
    FINGERPRINTS,
    INFO_LEAK_HEADERS,
    SECURITY_HEADERS,
    Fingerprint,
)
from .models import (
    Confidence,
    Evidence as Ev,          # the model Evidence (a piece of proof)
    HostFingerprint,
    Technology,
    clamp_confidence,
)

# How much each technique is trusted when a rule doesn't say otherwise.
_TECHNIQUE_WEIGHT = {
    "header": Confidence.STRONG,
    "any_header": Confidence.MEDIUM,
    "cookie": Confidence.STRONG,
    "meta_generator": Confidence.STRONG,
    "script": Confidence.STRONG,
    "body": Confidence.WEAK,
}

_META_GEN_RE = re.compile(
    r"<meta[^>]+name=['\"]generator['\"][^>]+content=['\"]([^'\"]+)['\"]", re.I
)
_META_GEN_RE2 = re.compile(
    r"<meta[^>]+content=['\"]([^'\"]+)['\"][^>]+name=['\"]generator['\"]", re.I
)
_SCRIPT_SRC_RE = re.compile(r"<script[^>]+src=['\"]([^'\"]+)['\"]", re.I)
_LINK_HREF_RE = re.compile(r"<link[^>]+href=['\"]([^'\"]+)['\"]", re.I)


# --------------------------------------------------------------------------- #
# Public entry
# --------------------------------------------------------------------------- #


def fingerprint(ev: Evidence) -> HostFingerprint:
    """Run every fingerprint over the evidence. Never raises."""
    fp = HostFingerprint(
        host=ev.host,
        url=ev.url,
        status_code=ev.status,
    )
    if ev.error and ev.status is None:
        fp.error = ev.error
        # Even with no HTTP, TLS may have succeeded - still record it.
        fp.tls = _summarise_tls(ev.tls)
        return fp

    # Pre-extract the derived surfaces once, not per-fingerprint.
    ctx = _Context(ev)

    detected: dict[str, Technology] = {}
    for f in FINGERPRINTS:
        _apply(f, ctx, detected)

    # Resolve "implies": a tech may pull in others (Laravel implies PHP) at a
    # modest confidence if they weren't already found on their own evidence.
    _resolve_implications(detected)

    fp.technologies = list(detected.values())

    # TLS + security headers are always-on analysis, independent of matches.
    fp.tls = _summarise_tls(ev.tls)
    _add_tls_technology(fp, ev)
    fp.security_headers = _analyse_security_headers(ev)

    return fp


# --------------------------------------------------------------------------- #
# Derived surfaces
# --------------------------------------------------------------------------- #


class _Context:
    """Everything a rule might match against, computed once from Evidence."""

    def __init__(self, ev: Evidence) -> None:
        self.ev = ev
        self.header_lines = [f"{k}: {v}" for k, v in ev.raw_header_pairs]
        self.header_blob = "\n".join(self.header_lines)
        self.cookies = ev.cookies
        self.body = ev.body
        self.scripts = _SCRIPT_SRC_RE.findall(ev.body) + _LINK_HREF_RE.findall(ev.body)
        self.generator = _meta_generator(ev.body)


def _meta_generator(body: str) -> str:
    m = _META_GEN_RE.search(body) or _META_GEN_RE2.search(body)
    return m.group(1) if m else ""


# --------------------------------------------------------------------------- #
# Rule application
# --------------------------------------------------------------------------- #


def _apply(f: Fingerprint, ctx: _Context, detected: dict[str, Technology]) -> None:
    ev = ctx.ev
    for rule in f.rules:
        # A rule dict can carry several keys; ALL keyed matchers in it must hit
        # (that lets us express "session cookie AND werkzeug server" = Flask).
        matched = True
        version: str | None = None
        proofs: list[tuple[str, str]] = []   # (technique, detail)

        for key, spec in rule.items():
            hit, ver, detail, technique = _match_one(key, spec, ctx, ev)
            if not hit:
                matched = False
                break
            if ver and not version:
                version = ver
            if detail:
                proofs.append((technique, detail))

        if not matched or not proofs:
            continue

        tech = detected.get(f.name.lower())
        if tech is None:
            tech = Technology(name=f.name, category=f.category)
            detected[f.name.lower()] = tech

        for technique, detail in proofs:
            weight = _TECHNIQUE_WEIGHT.get(technique, Confidence.MEDIUM)
            tech.add_evidence(Ev(technique=technique, detail=detail, confidence=int(weight)))
            if version:
                # Record which technique yielded which version (Phase 2 input).
                tech.version_candidates[technique] = version


def _match_one(key: str, spec, ctx: _Context, ev: Evidence):
    """Return (matched, version, detail, technique)."""
    if key == "header":
        name, pat = spec
        val = ev.header(name)
        if val:
            m = re.search(pat, val, re.I)
            if m:
                return True, _grp(m), f"{name.title()}: {val[:120]}", "header"
        return False, None, "", "header"

    if key == "any_header":
        m = re.search(spec, ctx.header_blob, re.I)
        if m:
            line = _line_of(ctx, m.start())
            return True, _grp(m), line[:120], "any_header"
        return False, None, "", "any_header"

    if key == "cookie":
        for name in ctx.cookies:
            m = re.search(spec, name, re.I)
            if m:
                return True, _grp(m), f"Set-Cookie: {name}", "cookie"
        return False, None, "", "cookie"

    if key == "meta_generator":
        if ctx.generator:
            m = re.search(spec, ctx.generator, re.I)
            if m:
                return True, _grp(m), f"<meta generator>: {ctx.generator[:100]}", "meta_generator"
        return False, None, "", "meta_generator"

    if key == "script":
        for src in ctx.scripts:
            m = re.search(spec, src, re.I)
            if m:
                return True, _grp(m), f"asset: {src[:120]}", "script"
        return False, None, "", "script"

    if key == "body":
        m = re.search(spec, ctx.body, re.I)
        if m:
            snippet = ctx.body[max(0, m.start() - 10): m.start() + 60].replace("\n", " ")
            return True, _grp(m), f"body: ...{snippet.strip()[:100]}...", "body"
        return False, None, "", "body"

    return False, None, "", key


def _grp(m: re.Match) -> str | None:
    """Return the captured 'ver' group, or None if the pattern has no such group."""
    if "ver" not in m.re.groupindex:
        return None
    v = m.group("ver")
    return v or None


def _line_of(ctx: _Context, pos: int) -> str:
    start = ctx.header_blob.rfind("\n", 0, pos) + 1
    end = ctx.header_blob.find("\n", pos)
    if end == -1:
        end = len(ctx.header_blob)
    return ctx.header_blob[start:end]


# --------------------------------------------------------------------------- #
# Implications
# --------------------------------------------------------------------------- #


def _resolve_implications(detected: dict[str, Technology]) -> None:
    from .fingerprints import FINGERPRINTS as _FPS

    by_name = {f.name.lower(): f for f in _FPS}
    catalog = {f.name.lower(): f for f in _FPS}

    added = True
    while added:
        added = False
        for key in list(detected.keys()):
            f = by_name.get(key)
            if not f:
                continue
            for implied in f.implies:
                ik = implied.lower()
                if ik in detected:
                    continue
                spec = catalog.get(ik)
                cat = spec.category if spec else "other"
                t = Technology(name=implied, category=cat, confidence=Confidence.WEAK)
                t.add_evidence(
                    Ev(technique="implied", detail=f"implied by {f.name}", confidence=Confidence.WEAK)
                )
                detected[ik] = t
                added = True


# --------------------------------------------------------------------------- #
# TLS + security headers
# --------------------------------------------------------------------------- #


def _summarise_tls(tls: dict) -> dict:
    if not tls or tls.get("error"):
        return tls or {}
    return tls


def _add_tls_technology(fp: HostFingerprint, ev: Evidence) -> None:
    tls = ev.tls or {}
    if not tls or tls.get("error"):
        return
    version = tls.get("tls_version", "")
    tech = Technology(name="TLS", category="tls", version=version or None,
                      confidence=Confidence.CERTAIN)
    if version:
        tech.add_evidence(Ev("tls", f"negotiated {version}", Confidence.CERTAIN))
    if tls.get("cipher"):
        tech.add_evidence(Ev("tls", f"cipher {tls['cipher']}", Confidence.STRONG))
    if tls.get("issuer_org") or tls.get("issuer_cn"):
        issuer = tls.get("issuer_org") or tls.get("issuer_cn")
        tech.add_evidence(Ev("tls", f"issuer {issuer}", Confidence.STRONG))
    # Flag weak/legacy protocol versions - a real security signal.
    if version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
        tech.add_evidence(Ev("tls", f"DEPRECATED protocol {version} in use", Confidence.CERTAIN))
    if tls.get("verified") is False:
        detail = tls.get("verify_error", "certificate not trusted")
        tech.add_evidence(Ev("tls", f"cert NOT trusted: {detail}", Confidence.STRONG))
    fp.technologies.append(tech)


def _analyse_security_headers(ev: Evidence) -> dict:
    present: dict[str, str] = {}
    missing: list[str] = []
    for header, why in SECURITY_HEADERS.items():
        val = ev.header(header)
        if val:
            present[header] = val[:160]
        else:
            missing.append(header)

    leaks: dict[str, str] = {}
    for header in INFO_LEAK_HEADERS:
        val = ev.header(header)
        if val:
            leaks[header] = val[:160]

    # A simple grade so the report can lead with a headline.
    score = len(present)
    total = len(SECURITY_HEADERS)
    if score >= total - 1:
        grade = "A"
    elif score >= total * 0.6:
        grade = "B"
    elif score >= total * 0.3:
        grade = "C"
    elif score >= 1:
        grade = "D"
    else:
        grade = "F"

    return {
        "grade": grade,
        "present": present,
        "missing": missing,
        "info_leaks": leaks,
    }
