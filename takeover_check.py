#!/usr/bin/env python3
"""
SubHunter takeover-check - subdomain takeover reconnaissance.

Reads a list of dead subdomains, gathers the evidence a human (or an AI) needs
to judge a potential subdomain takeover - CNAME chain, provider, HTTP status,
tell-tale headers, and the top of the response body - and writes it all into a
single consolidated report.

This tool does NOT decide whether a takeover is possible. It collects; you judge.

Author : Savaid Khan
Version: 1.0.0
License: MIT
Target : Linux (uses `dig`; degrades gracefully if absent)
"""

from __future__ import annotations

import argparse
import concurrent.futures
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

__author__ = "Savaid Khan"
__version__ = "1.0.0"

DEFAULT_INPUT = "dead_subdomains.txt"
DEFAULT_OUTPUT = "takeover_report.txt"
BODY_CHARS = 1000
SEP = "=" * 40

# --------------------------------------------------------------------------- #
# Provider fingerprints
# --------------------------------------------------------------------------- #

# Ordered longest-suffix-first so "s3-website.us-east-1.amazonaws.com" is
# matched before a hypothetical bare "amazonaws.com" rule. Each entry maps a
# CNAME-target suffix to a human-readable provider name.
PROVIDER_SUFFIXES: list[tuple[str, str]] = [
    # GitHub
    (".github.io", "GitHub Pages"),
    (".github.com", "GitHub"),
    # Heroku
    (".herokuapp.com", "Heroku"),
    (".herokudns.com", "Heroku"),
    (".herokussl.com", "Heroku"),
    # AWS
    (".s3-website.amazonaws.com", "AWS S3"),
    (".s3-website-us-east-1.amazonaws.com", "AWS S3"),
    (".s3.amazonaws.com", "AWS S3"),
    (".s3-external-1.amazonaws.com", "AWS S3"),
    (".amazonaws.com", "AWS"),
    (".cloudfront.net", "AWS CloudFront"),
    (".elasticbeanstalk.com", "AWS Elastic Beanstalk"),
    # Netlify
    (".netlify.app", "Netlify"),
    (".netlify.com", "Netlify"),
    # Azure
    (".azurewebsites.net", "Azure App Service"),
    (".cloudapp.net", "Azure"),
    (".cloudapp.azure.com", "Azure"),
    (".trafficmanager.net", "Azure Traffic Manager"),
    (".blob.core.windows.net", "Azure Blob Storage"),
    (".azureedge.net", "Azure CDN"),
    (".azurefd.net", "Azure Front Door"),
    (".azure-api.net", "Azure API Management"),
    # Fastly
    (".fastly.net", "Fastly"),
    (".fastlylb.net", "Fastly"),
    # CDNs / PaaS
    (".ghost.io", "Ghost"),
    (".pantheonsite.io", "Pantheon"),
    (".wpengine.com", "WP Engine"),
    (".zendesk.com", "Zendesk"),
    (".desk.com", "Desk"),
    (".surge.sh", "Surge.sh"),
    (".bitbucket.io", "Bitbucket"),
    (".gitlab.io", "GitLab Pages"),
    (".readthedocs.io", "Read the Docs"),
    (".readme.io", "Readme.io"),
    (".helpscoutdocs.com", "Help Scout"),
    (".statuspage.io", "Statuspage"),
    (".uservoice.com", "UserVoice"),
    (".wufoo.com", "Wufoo"),
    (".tumblr.com", "Tumblr"),
    (".shopify.com", "Shopify"),
    (".myshopify.com", "Shopify"),
    (".unbounce.com", "Unbounce"),
    (".instapage.com", "Instapage"),
    (".launchrock.com", "LaunchRock"),
    (".cargocollective.com", "Cargo"),
    (".webflow.io", "Webflow"),
    (".firebaseapp.com", "Firebase"),
    (".web.app", "Firebase Hosting"),
    (".pages.dev", "Cloudflare Pages"),
    (".workers.dev", "Cloudflare Workers"),
    (".render.com", "Render"),
    (".onrender.com", "Render"),
    (".vercel.app", "Vercel"),
    (".now.sh", "Vercel"),
    (".fly.dev", "Fly.io"),
    (".ondigitalocean.app", "DigitalOcean App Platform"),
    (".fastmail.com", "Fastmail"),
    (".freshdesk.com", "Freshdesk"),
    (".teamwork.com", "Teamwork"),
    (".aftership.com", "AfterShip"),
    (".bigcartel.com", "Big Cartel"),
    (".campaignmonitor.com", "Campaign Monitor"),
    (".createsend.com", "Campaign Monitor"),
    (".acquia-sites.com", "Acquia"),
    (".zohohost.com", "Zoho"),
    (".gitbook.io", "GitBook"),
    (".intercom.help", "Intercom"),
    (".proxy.webflow.com", "Webflow"),
]


def infer_provider(cname_target: str) -> str:
    """Map a CNAME target to a hosting provider, or UNKNOWN."""
    if not cname_target:
        return "UNKNOWN"
    host = cname_target.rstrip(".").lower()
    for suffix, name in PROVIDER_SUFFIXES:
        if host.endswith(suffix) or host == suffix.lstrip("."):
            return name
    return "UNKNOWN"


# --------------------------------------------------------------------------- #
# Logging (stderr - stdout stays clean for the report path if piped)
# --------------------------------------------------------------------------- #

_err_lock = threading.Lock()


def log(msg: str) -> None:
    with _err_lock:
        print(msg, file=sys.stderr, flush=True)


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #


@dataclass
class HostReport:
    subdomain: str
    cname_target: str = ""
    provider: str = "UNKNOWN"
    dig_output: str = ""
    nxdomain: bool | None = None
    http_status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    notes: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# dig / CNAME resolution
# --------------------------------------------------------------------------- #

_HOST_RE = re.compile(r"^[a-z0-9_-]+(\.[a-z0-9_-]+)+\.?$", re.I)


def _run_dig(args: list[str], timeout: float) -> tuple[int, str, str]:
    """Run dig, never raise. Returns (rc, stdout, stderr). rc -1 = couldn't run."""
    try:
        proc = subprocess.run(
            ["dig", *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
            stdin=subprocess.DEVNULL,
            check=False,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except FileNotFoundError:
        return -1, "", "dig not found"
    except subprocess.TimeoutExpired:
        return -1, "", f"dig timed out after {timeout}s"
    except OSError as e:
        return -1, "", f"dig error: {e}"
    except Exception as e:  # noqa: BLE001
        return -1, "", f"dig unexpected error: {e}"


def dig_cname_chain(host: str, timeout: float, have_dig: bool) -> tuple[str, str, bool | None, list[str]]:
    """Collect the CNAME chain for `host`.

    Returns (dig_output, first_cname_target, final_nxdomain, notes).

    - dig_output: human-readable trace of the chain
    - first_cname_target: the immediate CNAME of `host` (the machine-matchable one)
    - final_nxdomain: True if the end of the chain is NXDOMAIN, False if it
      resolves, None if undetermined
    """
    notes: list[str] = []

    if not have_dig:
        # Fall back to the resolver so we still emit *something* useful.
        target, note = _cname_via_socket(host)
        if note:
            notes.append(note)
        nx = _nxdomain_via_socket(target or host)
        trace = f"; dig unavailable - used system resolver\n{host} CNAME -> {target or '(none)'}"
        return trace, target, nx, notes

    lines: list[str] = []
    first_target = ""
    current = host.rstrip(".")
    final_nx: bool | None = None
    seen: set[str] = set()

    # Walk the CNAME chain by hand so we can record every hop and spot the
    # NXDOMAIN at the end - that is the strongest takeover signal.
    for hop in range(10):
        if current.lower() in seen:
            notes.append(f"CNAME loop detected at {current}")
            break
        seen.add(current.lower())

        rc, out, err = _run_dig([current, "CNAME", "+noall", "+answer", "+comments"], timeout)
        if rc == -1:
            notes.append(err)
            lines.append(f"; {current}: dig failed ({err})")
            break

        status = _extract_dig_status(out)
        answer = _extract_cname_answer(out, current)

        lines.append(f"; hop {hop}: {current}  (status: {status or 'n/a'})")
        for a in answer["raw_lines"]:
            lines.append(a)

        if status == "NXDOMAIN":
            final_nx = True
            lines.append(f"; {current} -> NXDOMAIN")
            break

        nxt = answer["target"]
        if not nxt:
            # No further CNAME. Chain ends here; check if this name resolves.
            final_nx = _final_name_nxdomain(current, timeout)
            lines.append(f"; chain ends at {current} (nxdomain={final_nx})")
            break

        if hop == 0:
            first_target = nxt
        current = nxt.rstrip(".")

    if first_target == "" and host.rstrip(".") in seen:
        # No CNAME at all on the original host.
        first_target = ""

    return "\n".join(lines).strip(), first_target, final_nx, notes


def _extract_dig_status(dig_out: str) -> str | None:
    m = re.search(r";;\s*->>HEADER<<-.*?status:\s*([A-Z]+)", dig_out, re.S)
    return m.group(1) if m else None


def _extract_cname_answer(dig_out: str, queried: str) -> dict:
    """Pull CNAME answer records out of dig +answer output."""
    target = ""
    raw: list[str] = []
    for line in dig_out.splitlines():
        line = line.rstrip()
        if not line or line.startswith(";"):
            continue
        parts = line.split()
        # NAME TTL CLASS TYPE VALUE
        if len(parts) >= 5 and parts[3].upper() == "CNAME":
            raw.append(line)
            if not target:
                target = parts[4].rstrip(".")
    return {"target": target, "raw_lines": raw}


def _final_name_nxdomain(name: str, timeout: float) -> bool | None:
    """Ask dig for A/AAAA of the final name to see if it NXDOMAINs."""
    rc, out, _ = _run_dig([name, "A", "+noall", "+comments"], timeout)
    if rc == -1:
        return None
    status = _extract_dig_status(out)
    if status == "NXDOMAIN":
        return True
    if status == "NOERROR":
        return False
    return None


def _cname_via_socket(host: str) -> tuple[str, str]:
    """Best-effort CNAME lookup without dig. Returns (target, note)."""
    try:
        name, aliases, _ = socket.gethostbyname_ex(host)
        # aliases are the CNAME chain; name is the canonical endpoint.
        if name and name.rstrip(".").lower() != host.rstrip(".").lower():
            return name.rstrip("."), ""
        return "", "no CNAME found via system resolver"
    except socket.gaierror:
        return "", "system resolver: NXDOMAIN or resolution failure"
    except (socket.herror, OSError) as e:
        return "", f"system resolver error: {e}"


def _nxdomain_via_socket(name: str) -> bool | None:
    try:
        socket.getaddrinfo(name, None)
        return False
    except socket.gaierror as e:
        # EAI_NONAME / HOST_NOT_FOUND == does not exist.
        if e.errno in (socket.EAI_NONAME, getattr(socket, "EAI_NODATA", -5)):
            return True
        return None
    except (UnicodeError, OSError):
        return None


# --------------------------------------------------------------------------- #
# HTTP probe
# --------------------------------------------------------------------------- #

_PROVIDER_HEADER_RE = re.compile(r"^x-", re.I)


def _ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("DEFAULT@SECLEVEL=1")
    except ssl.SSLError:
        pass
    return ctx


_SSL_CTX = _ssl_context()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # We want to fingerprint the response AT this host, not wherever it points.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def http_probe(host: str, timeout: float) -> tuple[int | None, dict[str, str], str, list[str]]:
    """Fetch host over HTTPS then HTTP. Returns (status, headers, body, notes)."""
    notes: list[str] = []
    opener = urllib.request.build_opener(
        _NoRedirect, urllib.request.HTTPSHandler(context=_SSL_CTX)
    )
    ua = (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
    )

    last_err = ""
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": ua, "Accept": "*/*", "Connection": "close"},
            method="GET",
        )
        try:
            with opener.open(req, timeout=timeout) as resp:
                status = resp.status
                headers = _filter_headers(resp.headers)
                body = _read_body(resp)
                return status, headers, body, notes
        except urllib.error.HTTPError as e:
            # An HTTP error is still a real, fingerprintable response.
            headers = _filter_headers(e.headers) if e.headers else {}
            body = ""
            try:
                body = _decode_body(e.read(BODY_CHARS * 4))
            except Exception:  # noqa: BLE001
                pass
            return e.code, headers, body, notes
        except urllib.error.URLError as e:
            reason = getattr(e, "reason", e)
            if isinstance(reason, ssl.SSLError):
                last_err = f"{scheme}: TLS error ({reason})"
                continue
            last_err = f"{scheme}: {reason}"
            continue
        except (socket.timeout, TimeoutError):
            last_err = f"{scheme}: timed out after {timeout}s"
            continue
        except (ConnectionResetError, ConnectionRefusedError) as e:
            last_err = f"{scheme}: {e}"
            continue
        except OSError as e:
            last_err = f"{scheme}: {e}"
            continue
        except Exception as e:  # noqa: BLE001
            last_err = f"{scheme}: unexpected error: {e}"
            continue

    if last_err:
        notes.append(f"HTTP probe failed: {last_err}")
    return None, {}, "", notes


def _filter_headers(headers) -> dict[str, str]:
    """Keep only Server and X-* headers - the ones that reveal the host."""
    out: dict[str, str] = {}
    if headers is None:
        return out
    try:
        items = headers.items()
    except Exception:  # noqa: BLE001
        return out
    for k, v in items:
        if k.lower() == "server" or _PROVIDER_HEADER_RE.match(k):
            out[k] = v
    return out


def _read_body(resp) -> str:
    try:
        raw = resp.read(BODY_CHARS * 4)  # over-read; multibyte may shrink it
    except Exception:  # noqa: BLE001
        return ""
    return _decode_body(raw)


def _decode_body(raw: bytes) -> str:
    if not raw:
        return ""
    text = raw.decode("utf-8", errors="replace")
    # Collapse to something readable and cap at BODY_CHARS.
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text[:BODY_CHARS]


# --------------------------------------------------------------------------- #
# Per-host orchestration
# --------------------------------------------------------------------------- #


def process_host(host: str, timeout: float, have_dig: bool) -> HostReport:
    """Gather everything for one host. Never raises."""
    rep = HostReport(subdomain=host)
    try:
        dig_out, target, nx, dig_notes = dig_cname_chain(host, timeout, have_dig)
        rep.dig_output = dig_out
        rep.cname_target = target
        rep.nxdomain = nx
        rep.notes.extend(dig_notes)
        rep.provider = infer_provider(target)
    except Exception as e:  # noqa: BLE001
        rep.notes.append(f"CNAME collection error: {type(e).__name__}: {e}")

    try:
        status, headers, body, http_notes = http_probe(host, timeout)
        rep.http_status = status
        rep.headers = headers
        rep.body = body
        rep.notes.extend(http_notes)
    except Exception as e:  # noqa: BLE001
        rep.notes.append(f"HTTP collection error: {type(e).__name__}: {e}")

    return rep


# --------------------------------------------------------------------------- #
# Report rendering
# --------------------------------------------------------------------------- #


def render_block(rep: HostReport) -> str:
    lines: list[str] = []
    lines.append(SEP)
    lines.append(f"SUBDOMAIN: {rep.subdomain}")
    lines.append(SEP)

    lines.append(f"CNAME_TARGET: {rep.cname_target or '(none)'}")
    lines.append(f"PROVIDER: {rep.provider}")

    lines.append("DIG_OUTPUT:")
    lines.append(rep.dig_output if rep.dig_output else "(no dig output)")

    if rep.nxdomain is None:
        lines.append("NXDOMAIN: unknown")
    else:
        lines.append(f"NXDOMAIN: {'true' if rep.nxdomain else 'false'}")

    lines.append(f"HTTP_STATUS: {rep.http_status if rep.http_status is not None else 'none'}")

    lines.append("HEADERS:")
    if rep.headers:
        for k, v in rep.headers.items():
            lines.append(f"{k}: {v}")
    else:
        lines.append("(none captured)")

    lines.append(f"RESPONSE_BODY (first {BODY_CHARS} chars):")
    lines.append(rep.body if rep.body else "(empty)")

    for note in rep.notes:
        lines.append(f"NOTE: {note}")

    lines.append(SEP)
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Input
# --------------------------------------------------------------------------- #

_INPUT_HOST_RE = re.compile(r"^[a-z0-9_.-]+$", re.I)


def read_hosts(path: Path) -> list[str]:
    """Read one host per line. Tolerate comments, blanks, and stray URL cruft."""
    hosts: list[str] = []
    seen: set[str] = set()
    with path.open("r", errors="replace") as fh:
        for raw in fh:
            h = raw.strip()
            if not h or h.startswith("#"):
                continue
            # Be forgiving about pasted URLs / trailing junk.
            h = re.sub(r"^[a-z][a-z0-9+.-]*://", "", h, flags=re.I)
            h = h.split("/")[0].split()[0].strip().rstrip(".").lower()
            if not h or not _INPUT_HOST_RE.match(h):
                continue
            if h not in seen:
                seen.add(h)
                hosts.append(h)
    return hosts


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="takeover_check",
        description=(
            f"SubHunter takeover-check v{__version__} by {__author__} - "
            "collect subdomain-takeover evidence into one AI-ready report."
        ),
        epilog=(
            "examples:\n"
            "  takeover_check.py\n"
            "  takeover_check.py -i dead.txt -o report.txt\n"
            "  takeover_check.py -i subhunter_example.com/dead.txt --threads 20\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-i", "--input", default=DEFAULT_INPUT,
                   help=f"file of dead subdomains, one per line (default: {DEFAULT_INPUT})")
    p.add_argument("-o", "--output", default=DEFAULT_OUTPUT,
                   help=f"consolidated report file (default: {DEFAULT_OUTPUT})")
    p.add_argument("-t", "--threads", type=int, default=1,
                   help="concurrent workers (default: 1 = sequential)")
    p.add_argument("--timeout", type=float, default=10.0,
                   help="per-host timeout in seconds for dig and HTTP (default: 10)")
    p.add_argument("-v", "--version", action="version",
                   version=f"takeover_check {__version__} by {__author__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    in_path = Path(args.input)
    if not in_path.exists():
        log(f"[-] input file not found: {in_path}")
        log(f"[-] pass one with -i, or create {DEFAULT_INPUT} (one subdomain per line)")
        return 2
    if not in_path.is_file():
        log(f"[-] input path is not a file: {in_path}")
        return 2

    try:
        hosts = read_hosts(in_path)
    except OSError as e:
        log(f"[-] cannot read {in_path}: {e}")
        return 2

    if not hosts:
        log(f"[!] no usable subdomains in {in_path} - nothing to do")
        return 1

    if args.threads < 1:
        args.threads = 1
    if args.timeout < 1:
        args.timeout = 1.0

    have_dig = shutil.which("dig") is not None
    if not have_dig:
        log("[!] `dig` not found - falling back to the system resolver for CNAME data")
        log("[!] install it on Linux with:  sudo apt install -y dnsutils")

    total = len(hosts)
    log(f"[*] takeover-check v{__version__} by {__author__}")
    log(f"[*] {total} host(s) from {in_path}  ·  {args.threads} thread(s)  ·  {args.timeout:.0f}s timeout")

    reports: list[HostReport] = []

    if args.threads == 1:
        for idx, host in enumerate(hosts, 1):
            log(f"[{idx}/{total}] processing {host}")
            reports.append(_safe_process(host, args.timeout, have_dig))
    else:
        reports = _process_concurrent(hosts, args.timeout, have_dig, args.threads)

    # Write the consolidated report.
    out_path = Path(args.output)
    header = (
        f"# SubHunter takeover-check report\n"
        f"# generated: {datetime.now(timezone.utc).isoformat()}\n"
        f"# source: {in_path}\n"
        f"# hosts: {total}\n"
        f"# author: {__author__}\n\n"
    )
    body = "\n\n".join(render_block(r) for r in reports)
    try:
        out_path.write_text(header + body + "\n", encoding="utf-8")
    except OSError as e:
        log(f"[-] failed to write {out_path}: {e}")
        # Last-ditch: dump to stdout so the work isn't lost.
        print(header + body)
        return 1

    # Quick triage summary to stderr.
    likely = [r for r in reports if r.nxdomain and r.provider != "UNKNOWN"]
    log(f"[+] wrote {out_path}  ({len(reports)} blocks)")
    if likely:
        log(f"[+] {len(likely)} host(s) have NXDOMAIN + a known provider - review these first:")
        for r in likely[:20]:
            log(f"      - {r.subdomain}  ({r.provider})")
        if len(likely) > 20:
            log(f"      ... and {len(likely) - 20} more")
    else:
        log("[*] no host had both NXDOMAIN and a known provider - manual review still advised")
    return 0


def _safe_process(host: str, timeout: float, have_dig: bool) -> HostReport:
    """process_host is already crash-proof, but guard the guard."""
    try:
        return process_host(host, timeout, have_dig)
    except Exception as e:  # noqa: BLE001
        rep = HostReport(subdomain=host)
        rep.notes.append(f"fatal per-host error: {type(e).__name__}: {e}")
        return rep


def _process_concurrent(
    hosts: list[str], timeout: float, have_dig: bool, threads: int
) -> list[HostReport]:
    results: dict[str, HostReport] = {}
    done = 0
    total = len(hosts)
    lock = threading.Lock()

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(_safe_process, h, timeout, have_dig): h for h in hosts}
        for fut in concurrent.futures.as_completed(futures):
            host = futures[fut]
            with lock:
                done += 1
                log(f"[{done}/{total}] processing {host}")
            try:
                results[host] = fut.result()
            except Exception as e:  # noqa: BLE001
                rep = HostReport(subdomain=host)
                rep.notes.append(f"worker error: {type(e).__name__}: {e}")
                results[host] = rep

    # Preserve the input order in the report even though work finished out of order.
    return [results[h] for h in hosts if h in results]


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        log("\n[-] aborted by user")
        sys.exit(130)
