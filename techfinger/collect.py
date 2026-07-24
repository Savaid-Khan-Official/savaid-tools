#!/usr/bin/env python3
"""
Evidence collection: one network round-trip per host.

Everything the fingerprint engine reasons about is gathered here, once, into an
`Evidence` bundle: HTTP status, response headers, Set-Cookie names, the top of
the HTML body, the redirect target, and the TLS certificate. Keeping all I/O in
this one module means the engine (engine.py) is pure, testable string logic.

Reuses the same lenient-TLS + no-redirect approach as subhunter.probe_http and
takeover_check.http_probe so behaviour is consistent across the toolkit.

Author : Savaid Khan
License: MIT
"""

from __future__ import annotations

import re
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field

__version__ = "1.0.0"

# How much HTML to pull. Fingerprints (generator meta, script srcs, inline lib
# banners) live near the top; 200 KB is plenty without downloading whole apps.
BODY_BYTES = 200_000
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
)


# --------------------------------------------------------------------------- #
# Evidence bundle
# --------------------------------------------------------------------------- #


@dataclass
class Evidence:
    """Raw, un-interpreted signals gathered from one host."""

    host: str
    url: str = ""
    scheme: str = ""
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)   # lower-cased keys
    raw_header_pairs: list[tuple[str, str]] = field(default_factory=list)
    cookies: list[str] = field(default_factory=list)        # cookie names only
    body: str = ""
    body_lower: str = ""
    redirect_location: str = ""
    tls: dict = field(default_factory=dict)                 # cert summary
    error: str = ""

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")


# --------------------------------------------------------------------------- #
# TLS
# --------------------------------------------------------------------------- #


def _lenient_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("DEFAULT@SECLEVEL=1")
    except ssl.SSLError:
        pass
    return ctx


_SSL_CTX = _lenient_ctx()


def collect_tls(host: str, timeout: float, port: int = 443) -> dict:
    """Grab the certificate + negotiated protocol. Returns {} on failure.

    Uses a verifying context first (so we can report the real cert), and falls
    back to a non-verifying one only to read the cert of a mis-configured host.
    """
    info: dict = {}
    # A verifying handshake tells us whether the cert is actually trusted.
    verify_ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with verify_ctx.wrap_socket(sock, server_hostname=host) as ss:
                info["verified"] = True
                info["tls_version"] = ss.version()
                cipher = ss.cipher()
                if cipher:
                    info["cipher"] = cipher[0]
                _summarise_cert(ss.getpeercert(), info)
                return info
    except (ssl.SSLError, ssl.CertificateError) as e:
        info["verified"] = False
        info["verify_error"] = str(e)[:160]
    except (socket.timeout, TimeoutError):
        return {"error": "tls: timed out"}
    except (ConnectionError, OSError) as e:
        return {"error": f"tls: {e}"}
    except Exception as e:  # noqa: BLE001
        return {"error": f"tls: {type(e).__name__}: {e}"}

    # Retry without verification just to read the (untrusted) cert details.
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with _SSL_CTX.wrap_socket(sock, server_hostname=host) as ss:
                info["tls_version"] = ss.version()
                cipher = ss.cipher()
                if cipher:
                    info["cipher"] = cipher[0]
                # An unverified handshake yields no parsed cert dict; note that.
                info.setdefault("note", "certificate not trusted by system store")
    except Exception:  # noqa: BLE001
        pass
    return info


def _summarise_cert(cert: dict | None, info: dict) -> None:
    if not cert:
        return
    subject = dict(x[0] for x in cert.get("subject", []) if x)
    issuer = dict(x[0] for x in cert.get("issuer", []) if x)
    info["subject_cn"] = subject.get("commonName", "")
    info["issuer_cn"] = issuer.get("commonName", "")
    info["issuer_org"] = issuer.get("organizationName", "")
    info["not_before"] = cert.get("notBefore", "")
    info["not_after"] = cert.get("notAfter", "")
    sans = [v for (t, v) in cert.get("subjectAltName", []) if t == "DNS"]
    info["san"] = sans[:15]


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def collect_evidence(
    host: str,
    *,
    timeout: float = 10.0,
    url: str | None = None,
    insecure: bool = True,
) -> Evidence:
    """Perform the single fetch and package everything up. Never raises."""
    ev = Evidence(host=host)

    schemes = ["https", "http"]
    if url:
        # Honour an explicit URL if SubHunter already found the working scheme.
        m = re.match(r"^([a-z]+)://", url, re.I)
        if m:
            schemes = [m.group(1).lower()] + [s for s in schemes if s != m.group(1).lower()]

    opener = urllib.request.build_opener(
        _NoRedirect, urllib.request.HTTPSHandler(context=_SSL_CTX)
    )

    last_err = ""
    for scheme in schemes:
        target = f"{scheme}://{host}"
        req = urllib.request.Request(
            target,
            headers={"User-Agent": USER_AGENT, "Accept": "*/*", "Connection": "close"},
            method="GET",
        )
        try:
            with opener.open(req, timeout=timeout) as resp:
                _fill_from_response(ev, resp, target, scheme, resp.status)
                break
        except urllib.error.HTTPError as e:
            # A 4xx/5xx is still a real, fingerprintable response.
            _fill_from_response(ev, e, target, scheme, e.code)
            break
        except urllib.error.URLError as e:
            reason = getattr(e, "reason", e)
            if isinstance(reason, ssl.SSLError) and scheme == "https":
                # Something is listening on 443, just badly. Note and try http.
                last_err = f"https TLS error: {reason}"
                continue
            last_err = f"{scheme}: {reason}"
            continue
        except (socket.timeout, TimeoutError):
            last_err = f"{scheme}: timed out"
            continue
        except (ConnectionError, OSError) as e:
            last_err = f"{scheme}: {e}"
            continue
        except Exception as e:  # noqa: BLE001
            last_err = f"{scheme}: {type(e).__name__}: {e}"
            continue

    if ev.status is None and not ev.url:
        ev.error = last_err or "no HTTP/HTTPS response"

    # TLS is independent of whether HTTP succeeded - collect it if 443 answers.
    try:
        ev.tls = collect_tls(host, min(timeout, 10.0))
    except Exception as e:  # noqa: BLE001
        ev.tls = {"error": f"tls: {e}"}

    return ev


def _fill_from_response(ev: Evidence, resp, url: str, scheme: str, status: int) -> None:
    ev.url = url
    ev.scheme = scheme
    ev.status = status

    headers = getattr(resp, "headers", None)
    pairs: list[tuple[str, str]] = []
    if headers is not None:
        try:
            pairs = list(headers.items())
        except Exception:  # noqa: BLE001
            pairs = []
    ev.raw_header_pairs = [(k, v) for k, v in pairs]
    # Last-wins flatten for easy lookup; keep raw pairs for multi-value headers.
    ev.headers = {k.lower(): v for k, v in pairs}
    ev.redirect_location = ev.headers.get("location", "")

    # Cookie names are a strong fingerprint (PHPSESSID, wordpress_*, ...).
    ev.cookies = _cookie_names(pairs)

    ev.body = _read_body(resp)
    ev.body_lower = ev.body.lower()


def _cookie_names(pairs: list[tuple[str, str]]) -> list[str]:
    names: list[str] = []
    for k, v in pairs:
        if k.lower() != "set-cookie":
            continue
        name = v.split("=", 1)[0].strip()
        if name and name not in names:
            names.append(name)
    return names


def _read_body(resp) -> str:
    try:
        raw = resp.read(BODY_BYTES)
    except Exception:  # noqa: BLE001
        return ""
    if not raw:
        return ""
    return raw.decode("utf-8", errors="replace")
