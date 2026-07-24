#!/usr/bin/env python3
"""
Data model for the technology-fingerprinting module.

Mirrors the dataclass style used by Subdomain (subhunter.py) and HostReport
(takeover_check.py): plain dataclasses, sets for de-duplicated provenance, and
a to_dict() that produces JSON-friendly output.

Author : Savaid Khan
Version: 1.0.0
License: MIT
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import IntEnum


# --------------------------------------------------------------------------- #
# Confidence
# --------------------------------------------------------------------------- #

# Confidence is an integer 0-100. Rather than sprinkle magic numbers through
# the engine, techniques assign one of these tiers and the merge step in
# versions.py combines them. Higher = stronger, harder-to-spoof evidence.


class Confidence(IntEnum):
    WEAK = 25       # a vague hint: a generic header value, a guessed cookie
    MEDIUM = 50     # a decent signal: a generator meta tag, a known cookie name
    STRONG = 75     # a specific artefact: a versioned asset path, a WAF header
    CERTAIN = 95    # unmistakable: an exact version string echoed by the server


def clamp_confidence(value: int) -> int:
    return max(0, min(100, int(value)))


# --------------------------------------------------------------------------- #
# Categories
# --------------------------------------------------------------------------- #

# The technology "kind". Kept as plain strings (not an enum) so extending the
# fingerprint DB never needs a code change - a new category is just a new
# string. These are the buckets the report groups by.

CATEGORIES = (
    "web-server",
    "server-version",
    "operating-system",
    "programming-language",
    "framework",
    "cms",
    "javascript-library",
    "css-framework",
    "reverse-proxy",
    "cdn",
    "waf",
    "api",
    "analytics",
    "authentication",
    "build-tool",
    "package-manager",
    "tls",
    "security-header",
    "other",
)


# --------------------------------------------------------------------------- #
# Evidence
# --------------------------------------------------------------------------- #


@dataclass
class Evidence:
    """One reason we believe a technology is present.

    technique: which detector fired ("header", "cookie", "html", "script",
               "meta", "tls", "security-header").
    detail:    the human-readable proof, e.g. 'Server: nginx/1.18.0'.
    confidence: how much this single piece of evidence is worth (0-100).
    """

    technique: str
    detail: str
    confidence: int = Confidence.MEDIUM

    def to_dict(self) -> dict:
        return {
            "technique": self.technique,
            "detail": self.detail[:300],
            "confidence": clamp_confidence(self.confidence),
        }


# --------------------------------------------------------------------------- #
# Vulnerability (Phase 3 output)
# --------------------------------------------------------------------------- #


@dataclass
class Vulnerability:
    cve_id: str
    cvss_score: float | None = None
    cvss_vector: str = ""
    severity: str = "UNKNOWN"          # CRITICAL / HIGH / MEDIUM / LOW / NONE
    description: str = ""
    published: str = ""
    has_public_exploit: bool = False
    has_metasploit_module: bool = False
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["description"] = self.description[:400]
        d["references"] = self.references[:5]
        return d


# --------------------------------------------------------------------------- #
# Technology (Phase 1 / Phase 2 output)
# --------------------------------------------------------------------------- #


@dataclass
class Technology:
    """A single detected technology, merged across every technique that saw it."""

    name: str
    category: str = "other"
    version: str | None = None
    confidence: int = Confidence.MEDIUM
    evidence: list[Evidence] = field(default_factory=list)

    # Phase 2 keeps a per-technique record of the versions that were seen so the
    # report can show how the final version was chosen.
    version_candidates: dict[str, str] = field(default_factory=dict)

    # Phase 3 enrichment.
    cpe: str | None = None                       # inferred CPE for CVE lookup
    end_of_life: bool | None = None              # None = unknown / not checked
    eol_detail: str = ""
    recommended_version: str | None = None
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    intel_status: str = ""                       # "", "ok", or an error reason

    # -- helpers ---------------------------------------------------------- #

    def add_evidence(self, ev: Evidence) -> None:
        self.evidence.append(ev)

    @property
    def key(self) -> str:
        """Merge key: two detections of the same tool collapse into one."""
        return self.name.strip().lower()

    @property
    def max_cvss(self) -> float | None:
        scores = [v.cvss_score for v in self.vulnerabilities if v.cvss_score is not None]
        return max(scores) if scores else None

    @property
    def worst_severity(self) -> str:
        order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "NONE": 1, "UNKNOWN": 0}
        if not self.vulnerabilities:
            return "NONE"
        return max((v.severity for v in self.vulnerabilities), key=lambda s: order.get(s, 0))

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "category": self.category,
            "version": self.version,
            "confidence": clamp_confidence(self.confidence),
            "evidence": [e.to_dict() for e in self.evidence],
            "version_candidates": self.version_candidates,
            "cpe": self.cpe,
            "end_of_life": self.end_of_life,
            "eol_detail": self.eol_detail,
            "recommended_version": self.recommended_version,
            "intel_status": self.intel_status,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
        }


# --------------------------------------------------------------------------- #
# Per-host finding
# --------------------------------------------------------------------------- #


@dataclass
class HostFingerprint:
    """Everything discovered for one live host."""

    host: str
    url: str = ""
    status_code: int | None = None
    ip: str = ""
    error: str = ""                              # set if collection failed outright
    technologies: list[Technology] = field(default_factory=list)

    # Raw security posture, surfaced even when no CVE is found.
    tls: dict = field(default_factory=dict)
    security_headers: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "url": self.url,
            "status_code": self.status_code,
            "ip": self.ip,
            "error": self.error,
            "tls": self.tls,
            "security_headers": self.security_headers,
            "technologies": [t.to_dict() for t in
                             sorted(self.technologies, key=lambda x: (x.category, x.name.lower()))],
        }
