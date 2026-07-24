#!/usr/bin/env python3
"""
Version validation - Phase 2.

Phase 1 can produce several version candidates for the same technology, each
from a different technique (a vague Server banner vs. an exact
`jquery-3.6.0.min.js` asset path). This module combines them:

  * the strongest technique wins,
  * corroboration (two techniques agreeing) boosts confidence,
  * a specific version never loses to a weaker one,
  * overall technology confidence is recomputed from the merged evidence.

It deliberately never invents a version: if nothing strong is present, it keeps
the best weak candidate but leaves confidence low so the report shows the doubt.

Author : Savaid Khan
License: MIT
"""

from __future__ import annotations

import re

from .models import HostFingerprint, Technology, clamp_confidence

# How much to trust a version depending on which technique produced it.
# A version echoed in a header or a versioned asset path is worth far more than
# one scraped out of body text.
_TECHNIQUE_VERSION_WEIGHT = {
    "header": 90,
    "meta_generator": 85,
    "script": 80,           # e.g. jquery-3.6.0.min.js
    "any_header": 60,
    "cookie": 40,
    "body": 35,
    "implied": 10,
}

_VER_RE = re.compile(r"^\d+(?:\.\d+){0,3}(?:[a-z]\d*)?$", re.I)


def validate_versions(fp: HostFingerprint) -> None:
    """Resolve each technology's final version + confidence in place."""
    for tech in fp.technologies:
        _resolve_one(tech)


def _resolve_one(tech: Technology) -> None:
    candidates = tech.version_candidates  # {technique: version}

    # 1) Confidence from evidence: base it on the single best piece plus a
    #    corroboration bonus for every additional independent technique.
    if tech.evidence:
        best = max(e.confidence for e in tech.evidence)
        techniques = {e.technique for e in tech.evidence}
        bonus = min(15, 5 * (len(techniques) - 1))
        tech.confidence = clamp_confidence(best + bonus)

    if not candidates:
        return

    # 2) Pick the best version: highest technique weight wins; ties broken by
    #    the more specific (more dotted components) string.
    def score(item: tuple[str, str]) -> tuple[int, int]:
        technique, ver = item
        weight = _TECHNIQUE_VERSION_WEIGHT.get(technique, 30)
        specificity = ver.count(".")
        return (weight, specificity)

    valid = {t: v for t, v in candidates.items() if _VER_RE.match(v)}
    pool = valid or candidates
    best_technique, best_version = max(pool.items(), key=score)
    tech.version = best_version

    # 3) Corroboration: if independent techniques agree on the same version,
    #    that's the strongest possible signal - push confidence near-certain.
    agreeing = [t for t, v in candidates.items() if v == best_version]
    if len(agreeing) >= 2:
        tech.confidence = clamp_confidence(max(tech.confidence, 90))
    elif _TECHNIQUE_VERSION_WEIGHT.get(best_technique, 0) >= 80:
        # A single strong source (exact header / versioned asset) is still solid.
        tech.confidence = clamp_confidence(max(tech.confidence, 80))
