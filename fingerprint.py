#!/usr/bin/env python3
"""
SubHunter fingerprint - standalone technology fingerprinting + security intel.

Companion to subhunter.py. Feed it a list of live subdomains (the live.txt a
scan produced, or any list of hosts, one per line) and it runs the techfinger
module over each: identifies technologies with confidence + evidence, validates
versions across techniques, and enriches every (technology, version) with CVEs,
CVSS, severity, EOL status, and public-exploit / Metasploit availability.

Mirrors takeover_check.py: same CLI shape, same "one clearly-delimited block
per host" report, same graceful degradation. Runs inline in subhunter.py via
--fingerprint, or standalone here against any live list.

    fingerprint.py -i subhunter_example.com/live.txt -o techfinger_report.txt
    fingerprint.py -i live.txt --threads 15
    fingerprint.py -i live.txt --offline          # Phase 1+2 only, no network intel

An optional NVD_API_KEY environment variable raises the CVE-lookup rate limit.

Author : Savaid Khan
Version: 1.0.0
License: MIT
"""

from __future__ import annotations

import argparse
import concurrent.futures
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

try:
    import techfinger
    from techfinger import report as tf_report
except ImportError as e:  # pragma: no cover
    sys.stderr.write(
        f"[-] cannot import the techfinger package: {e}\n"
        f"[-] run this script from the repository root so 'techfinger/' is importable\n"
    )
    sys.exit(2)

__author__ = "Savaid Khan"
__version__ = "1.0.0"

DEFAULT_INPUT = "live.txt"
DEFAULT_OUTPUT = "techfinger_report.txt"

_err_lock = threading.Lock()


def log(msg: str) -> None:
    with _err_lock:
        print(msg, file=sys.stderr, flush=True)


# --------------------------------------------------------------------------- #
# Input (same lenient parsing as takeover_check.read_hosts)
# --------------------------------------------------------------------------- #

import re

_HOST_RE = re.compile(r"^[a-z0-9_.-]+$", re.I)


def read_hosts(path: Path) -> list[str]:
    hosts: list[str] = []
    seen: set[str] = set()
    with path.open("r", errors="replace") as fh:
        for raw in fh:
            h = raw.strip()
            if not h or h.startswith("#"):
                continue
            h = re.sub(r"^[a-z][a-z0-9+.-]*://", "", h, flags=re.I)
            h = h.split("/")[0].split()[0].strip().rstrip(".").lower()
            if ":" in h:
                h = h.split(":")[0]
            if not h or not _HOST_RE.match(h):
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
        prog="fingerprint",
        description=(
            f"SubHunter fingerprint v{__version__} by {__author__} - technology "
            "fingerprinting + CVE/EOL/exploit intelligence for live subdomains."
        ),
        epilog=(
            "examples:\n"
            "  fingerprint.py -i subhunter_example.com/live.txt -o report.txt\n"
            "  fingerprint.py -i live.txt --threads 15\n"
            "  fingerprint.py -i live.txt --offline\n\n"
            "set NVD_API_KEY for a higher CVE-lookup rate limit.\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-i", "--input", default=DEFAULT_INPUT,
                   help=f"file of live hosts, one per line (default: {DEFAULT_INPUT})")
    p.add_argument("-o", "--output", default=DEFAULT_OUTPUT,
                   help=f"consolidated text report (default: {DEFAULT_OUTPUT})")
    p.add_argument("-j", "--json", default="",
                   help="also write a structured JSON report to this path")
    p.add_argument("-t", "--threads", type=int, default=10,
                   help="concurrent workers (default: 10)")
    p.add_argument("--timeout", type=float, default=10.0,
                   help="per-host HTTP/TLS timeout in seconds (default: 10)")
    p.add_argument("--offline", action="store_true",
                   help="skip online CVE/EOL/exploit lookups (Phase 1+2 only)")
    p.add_argument("-v", "--version", action="version",
                   version=f"fingerprint {__version__} by {__author__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    in_path = Path(args.input)
    if not in_path.exists():
        log(f"[-] input file not found: {in_path}")
        log(f"[-] pass one with -i, or point it at a scan's live.txt")
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
        log(f"[!] no usable hosts in {in_path} - nothing to do")
        return 1

    args.threads = max(1, min(args.threads, 50))
    if args.timeout < 1:
        args.timeout = 1.0
    online = not args.offline

    total = len(hosts)
    log(f"[*] fingerprint v{__version__} by {__author__}")
    log(f"[*] {total} host(s) from {in_path}  ·  {args.threads} thread(s)  ·  "
        f"{'online' if online else 'offline'} intel")

    fps = _run(hosts, args.timeout, args.threads, online, log)

    # Write reports.
    out_path = Path(args.output)
    try:
        out_path.write_text(tf_report.render_text(fps, str(in_path)), encoding="utf-8")
    except OSError as e:
        log(f"[-] failed to write {out_path}: {e}")
        print(tf_report.render_text(fps, str(in_path)))
        return 1

    written = [str(out_path)]
    if args.json:
        try:
            tf_report.write_json(fps, args.json, str(in_path))
            written.append(args.json)
        except OSError as e:
            log(f"[-] failed to write {args.json}: {e}")

    # Triage summary.
    n_tech = sum(len(f.technologies) for f in fps)
    n_cve = sum(len(t.vulnerabilities) for f in fps for t in f.technologies)
    eol = [(f.host, t) for f in fps for t in f.technologies if t.end_of_life]
    exploitable = [
        (f.host, t, v)
        for f in fps for t in f.technologies
        for v in t.vulnerabilities if v.has_public_exploit
    ]

    log(f"[+] wrote {', '.join(written)}  ({n_tech} technologies, {n_cve} CVEs)")
    if exploitable:
        log(f"[+] {len(exploitable)} CVE(s) with a public exploit - review these first:")
        for host, t, v in exploitable[:20]:
            msf = " +metasploit" if v.has_metasploit_module else ""
            log(f"      - {host}  {t.name} {t.version or ''}  {v.cve_id} "
                f"({v.severity}{msf})")
        if len(exploitable) > 20:
            log(f"      ... and {len(exploitable) - 20} more")
    if eol:
        log(f"[!] {len(eol)} end-of-life technology instance(s):")
        for host, t in eol[:15]:
            log(f"      - {host}  {t.name} {t.version or ''}")
    if not exploitable and not eol:
        log("[*] no public-exploit CVEs or EOL tech flagged - manual review still advised")
    return 0


def _run(hosts, timeout, threads, online, logfn):
    fps = []
    done = 0
    total = len(hosts)
    lock = threading.Lock()

    def work(host):
        return techfinger.fingerprint_and_enrich(host, timeout=timeout, online=online)

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(work, h): h for h in hosts}
        for fut in concurrent.futures.as_completed(futures):
            host = futures[fut]
            with lock:
                done += 1
                logfn(f"[{done}/{total}] {host}")
            try:
                fps.append(fut.result())
            except Exception as e:  # noqa: BLE001
                fp = techfinger.HostFingerprint(host=host, error=f"{type(e).__name__}: {e}")
                fps.append(fp)

    fps.sort(key=lambda f: f.host)
    return fps


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        log("\n[-] aborted by user")
        sys.exit(130)
