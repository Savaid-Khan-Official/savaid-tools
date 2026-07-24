#!/usr/bin/env python3
"""
SubHunter - Subdomain enumeration and liveness triage.

Takes a domain, runs whatever enumeration tools are installed on the box,
merges the results, and splits them into live and dead.

Author : Savaid Khan
Version: 1.0.0
License: MIT
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

__author__ = "Savaid Khan"
__version__ = "1.0.0"

# --------------------------------------------------------------------------- #
# Terminal colours
# --------------------------------------------------------------------------- #


class C:
    """ANSI colours, blanked out when the terminal can't handle them."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"

    @classmethod
    def disable(cls) -> None:
        for name in dir(cls):
            if name.isupper():
                setattr(cls, name, "")


def _init_colours(force: bool) -> None:
    if force:
        return
    if os.environ.get("NO_COLOR") is not None or not sys.stdout.isatty():
        C.disable()
        return
    if sys.platform == "win32":
        # Windows 10+ needs VT processing switched on explicitly.
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            C.disable()


BANNER = r"""
   _____       _     _   _             _
  / ____|     | |   | | | |           | |
 | (___  _   _| |__ | |_| |_   _ _ __ | |_ ___ _ __
  \___ \| | | | '_ \|  _  | | | | '_ \| __/ _ \ '__|
  ____) | |_| | |_) | | | | |_| | | | | ||  __/ |
 |_____/ \__,_|_.__/|_| |_|\__,_|_| |_|\__\___|_|
"""


def print_banner() -> None:
    out(f"{C.CYAN}{BANNER}{C.RESET}")
    out(f"  {C.BOLD}SubHunter v{__version__}{C.RESET}  ·  by {C.MAGENTA}{__author__}{C.RESET}")
    out(f"  {C.DIM}Subdomain enumeration + liveness triage{C.RESET}\n")


# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #

_log_lock = threading.Lock()
_QUIET = False


class _PipeClosed(Exception):
    """stdout went away - someone piped us into `head` and it exited."""


def out(msg: str = "") -> None:
    """print() that turns a closed pipe into a clean shutdown, not a traceback."""
    try:
        print(msg, flush=True)
    except BrokenPipeError:
        raise _PipeClosed from None
    except OSError as e:
        # Windows reports the same condition as EINVAL/EPIPE on a dead pipe.
        if e.errno in (22, 32):
            raise _PipeClosed from None
        raise


def _log(tag: str, colour: str, msg: str, *, force: bool = False) -> None:
    if _QUIET and not force:
        return
    with _log_lock:
        out(f"{colour}[{tag}]{C.RESET} {msg}")


def info(msg: str) -> None:
    _log("*", C.BLUE, msg)


def good(msg: str) -> None:
    _log("+", C.GREEN, msg)


def warn(msg: str) -> None:
    _log("!", C.YELLOW, msg)


def error(msg: str) -> None:
    with _log_lock:
        print(f"{C.RED}[-]{C.RESET} {msg}", file=sys.stderr, flush=True)


def step(msg: str) -> None:
    if _QUIET:
        return
    with _log_lock:
        out(f"\n{C.BOLD}{C.CYAN}==>{C.RESET} {C.BOLD}{msg}{C.RESET}")


# --------------------------------------------------------------------------- #
# Domain handling
# --------------------------------------------------------------------------- #

# Deliberately permissive: real-world subdomains include underscores (DMARC,
# DKIM selectors) and wildcards leak in from certificate transparency.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9_-]{1,63}(?<!-)(\.(?!-)[a-z0-9_-]{1,63}(?<!-))*$"
)


class DomainError(ValueError):
    """Raised when the user hands us something that isn't a usable domain."""


def normalise_domain(raw: str) -> str:
    """Turn user input into a bare, lowercase, punycode domain.

    Accepts things people actually paste: URLs, trailing dots, *.wildcards,
    uppercase, unicode, stray whitespace.
    """
    if raw is None:
        raise DomainError("no domain supplied")

    d = raw.strip().strip('"').strip("'")
    if not d:
        raise DomainError("domain is empty")

    # Strip scheme (including scheme-relative "//host") and anything after
    # the authority.
    d = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", d)
    d = d.lstrip("/")
    d = d.split("/")[0].split("?")[0].split("#")[0]

    # Strip creds and port.
    if "@" in d:
        d = d.rsplit("@", 1)[1]
    if d.startswith("["):  # bracketed IPv6
        raise DomainError("IP addresses are not valid enumeration targets")
    if ":" in d:
        d = d.split(":")[0]

    d = d.rstrip(".").lower()
    while d.startswith("*."):
        d = d[2:]

    if not d:
        raise DomainError("domain is empty after normalisation")

    # Reject IPs early - enumerating subdomains of an IP is meaningless.
    # Note: DomainError subclasses ValueError, so the raise must live outside
    # the try or this except would swallow it.
    is_ip = True
    try:
        ipaddress.ip_address(d)
    except ValueError:
        is_ip = False
    if is_ip:
        raise DomainError(f"{raw!r} is an IP address, not a domain")

    if len(d) > 253:
        raise DomainError(f"domain is {len(d)} chars, max is 253")
    if any(len(label) > 63 for label in d.split(".")):
        raise DomainError("a domain label exceeds 63 characters")

    # IDN -> punycode.
    try:
        d = d.encode("idna").decode("ascii").lower()
    except (UnicodeError, UnicodeDecodeError):
        raise DomainError(f"{raw!r} is not a valid international domain name")

    if not _HOSTNAME_RE.match(d):
        raise DomainError(f"{raw!r} is not a valid domain name")
    if "." not in d:
        raise DomainError(f"{raw!r} has no TLD - did you mean {d}.com?")

    return d


def clean_host(line: str, root: str) -> str | None:
    """Pull a valid in-scope hostname out of one line of tool output."""
    if not line:
        return None
    h = line.strip().strip('"').strip("'").lower()
    if not h or h.startswith("#"):
        return None

    # Tools emit varied shapes: "sub.example.com", "https://sub.example.com",
    # "sub.example.com,1.2.3.4", "[INF] sub.example.com".
    h = re.sub(r"^\[[^\]]*\]\s*", "", h)
    h = re.sub(r"^[a-z][a-z0-9+.-]*://", "", h)
    h = h.split("/")[0].split(",")[0].split()[0] if h.split() else ""
    if not h:
        return None
    while h.startswith("*."):
        h = h[2:]
    h = h.rstrip(".").strip()
    if ":" in h:
        h = h.split(":")[0]
    if not h or not _HOSTNAME_RE.match(h):
        return None
    # Scope guard: only keep the root itself and things under it.
    if h != root and not h.endswith("." + root):
        return None
    return h


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #


@dataclass
class Subdomain:
    host: str
    sources: set[str] = field(default_factory=set)
    ips: list[str] = field(default_factory=list)
    resolved: bool = False
    alive: bool = False
    status_code: int | None = None
    url: str | None = None
    title: str | None = None
    reason: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["sources"] = sorted(self.sources)
        return d


@dataclass
class ToolResult:
    name: str
    found: int = 0
    ok: bool = False
    detail: str = ""
    seconds: float = 0.0


# --------------------------------------------------------------------------- #
# Subprocess helper
# --------------------------------------------------------------------------- #

_INTERRUPTED = threading.Event()


def which(binary: str) -> str | None:
    try:
        return shutil.which(binary)
    except Exception:
        return None


def run_cmd(cmd: list[str], timeout: int) -> tuple[int, str, str]:
    """Run a command, never raise. Returns (rc, stdout, stderr).

    rc of -1 means it could not start, -2 means it timed out.
    """
    if _INTERRUPTED.is_set():
        return -1, "", "interrupted"
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
            stdin=subprocess.DEVNULL,
            check=False,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired:
        return -2, "", f"timed out after {timeout}s"
    except FileNotFoundError:
        return -1, "", f"{cmd[0]}: not found"
    except PermissionError:
        return -1, "", f"{cmd[0]}: permission denied"
    except OSError as e:
        return -1, "", f"{cmd[0]}: {e}"
    except Exception as e:  # noqa: BLE001 - a tool must never kill the run
        return -1, "", f"{cmd[0]}: unexpected error: {e}"


# --------------------------------------------------------------------------- #
# Enumeration sources
# --------------------------------------------------------------------------- #


class Source:
    """One way of discovering subdomains."""

    name = "source"
    binary: str | None = None

    def available(self) -> bool:
        return self.binary is None or which(self.binary) is not None

    def run(self, domain: str, timeout: int) -> tuple[set[str], str]:
        raise NotImplementedError


class _CmdSource(Source):
    """A source that shells out and reads hostnames off stdout."""

    def cmd(self, domain: str, tmpdir: str) -> list[str]:
        raise NotImplementedError

    def run(self, domain: str, timeout: int) -> tuple[set[str], str]:
        with tempfile.TemporaryDirectory(prefix="subhunter_") as tmp:
            cmd = self.cmd(domain, tmp)
            rc, out, err = run_cmd(cmd, timeout)
            if rc == -1:
                return set(), err
            if rc == -2:
                # A timeout still leaves us whatever it printed first.
                hosts = {h for h in (clean_host(l, domain) for l in out.splitlines()) if h}
                return hosts, f"timed out after {timeout}s (kept {len(hosts)})"

            extra = self.extra_output(tmp)
            hosts = {
                h
                for h in (clean_host(l, domain) for l in (out + "\n" + extra).splitlines())
                if h
            }
            if rc != 0 and not hosts:
                tail = (err or out).strip().splitlines()
                msg = tail[-1][:160] if tail else f"exit code {rc}"
                return set(), msg
            return hosts, ""

    def extra_output(self, tmpdir: str) -> str:
        """Some tools only write to a file; override to read it back."""
        return ""


class Subfinder(_CmdSource):
    name = "subfinder"
    binary = "subfinder"

    def cmd(self, domain: str, tmpdir: str) -> list[str]:
        return [self.binary, "-d", domain, "-silent", "-all"]


class Assetfinder(_CmdSource):
    name = "assetfinder"
    binary = "assetfinder"

    def cmd(self, domain: str, tmpdir: str) -> list[str]:
        return [self.binary, "--subs-only", domain]


class Findomain(_CmdSource):
    name = "findomain"
    binary = "findomain"

    def cmd(self, domain: str, tmpdir: str) -> list[str]:
        return [self.binary, "-t", domain, "-q"]


class CrtSh(Source):
    """Certificate transparency via crt.sh - no local tool needed."""

    name = "crt.sh"
    binary = None

    def run(self, domain: str, timeout: int) -> tuple[set[str], str]:
        url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
        req = urllib.request.Request(
            url, headers={"User-Agent": f"SubHunter/{__version__}", "Accept": "application/json"}
        )
        try:
            with _api_opener().open(req, timeout=min(timeout, 60)) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            return set(), f"HTTP {e.code} from crt.sh"
        except urllib.error.URLError as e:
            if _is_cert_error(e):
                return set(), "TLS certificate verification failed (try --insecure if behind a proxy)"
            return set(), f"network error: {e.reason}"
        except socket.timeout:
            return set(), "timed out"
        except Exception as e:  # noqa: BLE001
            return set(), f"{e}"

        if not raw.strip():
            return set(), "empty response"
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return set(), "crt.sh returned non-JSON (rate limited?)"

        hosts: set[str] = set()
        for entry in data if isinstance(data, list) else []:
            if not isinstance(entry, dict):
                continue
            for key in ("name_value", "common_name"):
                val = entry.get(key) or ""
                for line in str(val).splitlines():
                    h = clean_host(line, domain)
                    if h:
                        hosts.add(h)
        return hosts, ""


class HackerTarget(Source):
    """Free hostsearch API - a useful backstop when nothing else is installed."""

    name = "hackertarget"
    binary = None

    def run(self, domain: str, timeout: int) -> tuple[set[str], str]:
        url = f"https://api.hackertarget.com/hostsearch/?q={urllib.parse.quote(domain)}"
        req = urllib.request.Request(url, headers={"User-Agent": f"SubHunter/{__version__}"})
        try:
            with _api_opener().open(req, timeout=min(timeout, 45)) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            return set(), f"HTTP {e.code}"
        except urllib.error.URLError as e:
            if _is_cert_error(e):
                return set(), "TLS certificate verification failed (try --insecure if behind a proxy)"
            return set(), f"network error: {e.reason}"
        except Exception as e:  # noqa: BLE001
            return set(), f"{e}"

        if "API count exceeded" in raw or "error" in raw.lower()[:40]:
            return set(), "API quota exceeded"
        hosts = {h for h in (clean_host(l, domain) for l in raw.splitlines()) if h}
        return hosts, ""


PASSIVE_SOURCES: list[Source] = [
    Subfinder(),
    Assetfinder(),
    Findomain(),
    CrtSh(),
    HackerTarget(),
]


# --------------------------------------------------------------------------- #
# Brute force
# --------------------------------------------------------------------------- #

DEFAULT_WORDLIST_PATHS = [
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
    "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "/usr/share/dnsrecon/subdomains-top1mil-5000.txt",
    "/usr/share/wordlists/dnsmap.txt",
    "/usr/share/amass/wordlists/subdomains-top1mil-5000.txt",
]

# Small built-in list so brute force still does something without SecLists.
BUILTIN_WORDS = """www mail ftp localhost webmail smtp pop ns1 ns2 cpanel whm autodiscover
autoconfig m imap test ns blog pop3 dev www2 admin forum news vpn ns3 mail2 new mysql old
lists support mobile mx static docs beta shop sql secure demo cp calendar wiki web media
email images img www1 intranet portal video sip dns2 api cdn stats dns1 ns4 www3 dns search
staging server mx1 chat wap my svn mail1 sites proxy ads host crm cms backup mx2 lyncdiscover
info apps download remote db forums store relay files newsletter app live owa en start sms
office exchange ipv4 mail3 help blogs helpdesk web1 home library ftp2 ntp monitor login
service correo www4 moodle it gateway gw i staff smtp2 smtp1 firewall cloud archive jenkins
git gitlab jira confluence grafana kibana prometheus vault consul nexus sonar registry
docker k8s kubernetes staging1 uat qa sandbox preprod prod internal external partner
dashboard analytics metrics logs auth sso oauth idp saml ldap radius""".split()


def find_wordlist(explicit: str | None) -> tuple[list[str], str]:
    """Return (words, description-of-where-they-came-from)."""
    if explicit:
        p = Path(explicit)
        if not p.exists():
            raise DomainError(f"wordlist not found: {explicit}")
        if not p.is_file():
            raise DomainError(f"wordlist is not a file: {explicit}")
        try:
            words = _read_words(p)
        except OSError as e:
            raise DomainError(f"cannot read wordlist {explicit}: {e}")
        if not words:
            raise DomainError(f"wordlist is empty: {explicit}")
        return words, str(p)

    for cand in DEFAULT_WORDLIST_PATHS:
        p = Path(cand)
        try:
            if p.is_file():
                words = _read_words(p)
                if words:
                    return words, str(p)
        except OSError:
            continue

    return sorted(set(BUILTIN_WORDS)), "built-in list"


def _read_words(p: Path) -> list[str]:
    words: list[str] = []
    seen: set[str] = set()
    with p.open("r", errors="replace") as fh:
        for line in fh:
            w = line.strip().lower()
            if not w or w.startswith("#"):
                continue
            if w not in seen:
                seen.add(w)
                words.append(w)
    return words


# --------------------------------------------------------------------------- #
# DNS resolution
# --------------------------------------------------------------------------- #


def resolve(host: str, timeout: float = 5.0) -> list[str]:
    """Resolve a hostname to a list of IPs. Empty list means NXDOMAIN/failure."""
    if _INTERRUPTED.is_set():
        return []
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        ips: list[str] = []
        for fam, _, _, _, sockaddr in infos:
            ip = sockaddr[0]
            if ip not in ips:
                ips.append(ip)
        return ips
    except (socket.gaierror, socket.herror, socket.timeout, UnicodeError, OSError):
        return []
    except Exception:  # noqa: BLE001
        return []
    finally:
        try:
            socket.setdefaulttimeout(old)
        except Exception:
            pass


def detect_wildcard(domain: str, samples: int = 3) -> set[str]:
    """Return the IP set a wildcard record points at, or empty if no wildcard.

    Queries random hosts that cannot legitimately exist. If they resolve, the
    zone has a wildcard and every brute-forced name would be a false positive.
    """
    import random
    import string

    ip_sets: list[frozenset[str]] = []
    for _ in range(samples):
        rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=18))
        ips = resolve(f"{rand}.{domain}", timeout=5.0)
        if not ips:
            return set()  # a single NXDOMAIN proves there is no wildcard
        ip_sets.append(frozenset(ips))

    union: set[str] = set()
    for s in ip_sets:
        union |= s
    return union


# --------------------------------------------------------------------------- #
# HTTP probing
# --------------------------------------------------------------------------- #

_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)


def _make_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("DEFAULT@SECLEVEL=1")  # tolerate old/broken TLS
    except ssl.SSLError:
        pass
    return ctx


_SSL_CTX = _make_ssl_context()

# Context for the passive API sources. Verification stays ON by default -
# these are third-party feeds and we should notice a MITM. --insecure swaps
# it out for environments behind a TLS-intercepting proxy.
_API_SSL_CTX: ssl.SSLContext | None = None


def set_api_ssl_insecure() -> None:
    global _API_SSL_CTX
    _API_SSL_CTX = _make_ssl_context()


def _api_opener() -> urllib.request.OpenerDirector:
    if _API_SSL_CTX is not None:
        return urllib.request.build_opener(urllib.request.HTTPSHandler(context=_API_SSL_CTX))
    return urllib.request.build_opener()


def _is_cert_error(exc: BaseException) -> bool:
    reason = getattr(exc, "reason", exc)
    return isinstance(reason, ssl.SSLCertVerificationError) or "CERTIFICATE_VERIFY_FAILED" in str(reason)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def probe_http(host: str, timeout: float, ports: Iterable[str]) -> tuple[bool, int | None, str | None, str | None]:
    """Try HTTPS then HTTP. Returns (alive, status, url, title)."""
    if _INTERRUPTED.is_set():
        return False, None, None, None

    opener = urllib.request.build_opener(
        _NoRedirect,
        urllib.request.HTTPSHandler(context=_SSL_CTX),
    )
    for scheme in ports:
        url = f"{scheme}://{host}"
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
                ),
                "Accept": "*/*",
                "Connection": "close",
            },
            method="GET",
        )
        try:
            with opener.open(req, timeout=timeout) as resp:
                body = resp.read(8192)
                return True, resp.status, url, _extract_title(body)
        except urllib.error.HTTPError as e:
            # 4xx/5xx still means a server answered - that host is live.
            title = None
            try:
                title = _extract_title(e.read(8192))
            except Exception:  # noqa: BLE001
                pass
            # urllib synthesises a title-less body for bare redirects; don't
            # pass off "301 Moved Permanently" as if it were a page title.
            if title and _looks_like_status_line(title, e.code):
                title = None
            return True, e.code, url, title
        except urllib.error.URLError as e:
            reason = getattr(e, "reason", e)
            # A TLS error means something IS listening, just badly.
            if isinstance(reason, ssl.SSLError):
                return True, None, url, None
            continue
        except (socket.timeout, TimeoutError):
            continue
        except (ConnectionResetError, ConnectionRefusedError, OSError):
            continue
        except Exception:  # noqa: BLE001
            continue
    return False, None, None, None


def _looks_like_status_line(title: str, code: int | None) -> bool:
    """True if the "title" is really just an HTTP status line echoed back."""
    t = title.strip().lower()
    if code is not None and t.startswith(str(code)):
        return True
    return bool(re.match(r"^[1-5]\d{2}\s+[a-z ]+$", t))


def _extract_title(body: bytes) -> str | None:
    m = _TITLE_RE.search(body or b"")
    if not m:
        return None
    try:
        t = m.group(1).decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return None
    t = re.sub(r"\s+", " ", t).strip()
    return t[:80] or None


# --------------------------------------------------------------------------- #
# Progress
# --------------------------------------------------------------------------- #


class Progress:
    def __init__(self, total: int, label: str) -> None:
        self.total = max(total, 1)
        self.label = label
        self.done = 0
        self.lock = threading.Lock()
        self.enabled = sys.stdout.isatty() and not _QUIET

    def tick(self) -> None:
        with self.lock:
            self.done += 1
            if not self.enabled:
                return
            if self.done % 25 and self.done != self.total:
                return
            pct = self.done * 100 // self.total
            bar_w = 28
            filled = pct * bar_w // 100
            bar = "#" * filled + "-" * (bar_w - filled)
            try:
                sys.stdout.write(
                    f"\r  {C.DIM}{self.label}{C.RESET} [{C.CYAN}{bar}{C.RESET}] "
                    f"{pct:3d}%  {self.done}/{self.total}"
                )
                sys.stdout.flush()
            except (BrokenPipeError, OSError):
                self.enabled = False

    def close(self) -> None:
        if self.enabled:
            try:
                sys.stdout.write("\r" + " " * 78 + "\r")
                sys.stdout.flush()
            except (BrokenPipeError, OSError):
                self.enabled = False


# --------------------------------------------------------------------------- #
# Scanner
# --------------------------------------------------------------------------- #


class SubHunter:
    def __init__(self, args: argparse.Namespace) -> None:
        self.domain: str = args.domain
        self.args = args
        self.results: dict[str, Subdomain] = {}
        self.tool_results: list[ToolResult] = []
        self.wildcard_ips: set[str] = set()
        self.fingerprints: list = []
        self.started = datetime.now(timezone.utc)

    # -- discovery ---------------------------------------------------------- #

    def enumerate_passive(self) -> None:
        step("Passive enumeration")

        sources = [s for s in PASSIVE_SOURCES if s.name not in self.args.exclude]
        available = [s for s in sources if s.available()]
        missing = [s for s in sources if not s.available()]

        for s in missing:
            warn(f"{s.name:<14} not installed - skipping")
        if not available:
            warn("no passive sources available at all")
            return

        info(f"running {len(available)} source(s) in parallel")

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(available)) as pool:
            futures = {
                pool.submit(self._run_source, s): s for s in available
            }
            for fut in concurrent.futures.as_completed(futures):
                src = futures[fut]
                try:
                    fut.result()
                except _PipeClosed:
                    raise
                except Exception as e:  # noqa: BLE001
                    error(f"{src.name} crashed: {e}")
                    self.tool_results.append(ToolResult(src.name, 0, False, str(e)[:120]))

    def _run_source(self, src: Source) -> None:
        t0 = time.time()
        try:
            hosts, err = src.run(self.domain, self.args.timeout)
        except Exception as e:  # noqa: BLE001
            hosts, err = set(), f"unhandled: {e}"
        elapsed = time.time() - t0

        if err and not hosts:
            warn(f"{src.name:<14} failed: {err}")
            self.tool_results.append(ToolResult(src.name, 0, False, err[:120], elapsed))
            return
        if err:
            warn(f"{src.name:<14} partial: {err}")

        for h in hosts:
            self._add(h, src.name)
        good(f"{src.name:<14} {len(hosts):>5} found  {C.DIM}({elapsed:.1f}s){C.RESET}")
        self.tool_results.append(ToolResult(src.name, len(hosts), True, err[:120], elapsed))

    def enumerate_brute(self) -> None:
        step("Brute force")
        try:
            words, origin = find_wordlist(self.args.wordlist)
        except DomainError as e:
            error(str(e))
            return

        info(f"wordlist: {origin} ({len(words):,} words)")

        if self.wildcard_ips:
            warn(
                f"wildcard DNS detected ({', '.join(sorted(self.wildcard_ips)[:3])}) - "
                "brute force results will be filtered"
            )

        candidates = [f"{w}.{self.domain}" for w in words]
        prog = Progress(len(candidates), "brute")
        found = 0

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.args.threads) as pool:
                futures = {pool.submit(resolve, h, 5.0): h for h in candidates}
                for fut in concurrent.futures.as_completed(futures):
                    host = futures[fut]
                    prog.tick()
                    if _INTERRUPTED.is_set():
                        break
                    try:
                        ips = fut.result()
                    except Exception:  # noqa: BLE001
                        continue
                    if not ips:
                        continue
                    if self.wildcard_ips and set(ips) <= self.wildcard_ips:
                        continue  # wildcard false positive
                    sub = self._add(host, "bruteforce")
                    sub.ips = ips
                    sub.resolved = True
                    found += 1
        except KeyboardInterrupt:
            _INTERRUPTED.set()
        finally:
            prog.close()

        good(f"{'bruteforce':<14} {found:>5} found")
        self.tool_results.append(ToolResult("bruteforce", found, True, origin))

    def _add(self, host: str, source: str) -> Subdomain:
        sub = self.results.get(host)
        if sub is None:
            sub = Subdomain(host=host)
            self.results[host] = sub
        sub.sources.add(source)
        return sub

    # -- triage ------------------------------------------------------------- #

    def check_wildcard(self) -> None:
        step("Wildcard check")
        try:
            self.wildcard_ips = detect_wildcard(self.domain)
        except Exception as e:  # noqa: BLE001
            warn(f"wildcard check failed: {e}")
            self.wildcard_ips = set()
            return
        if self.wildcard_ips:
            warn(f"*.{self.domain} resolves to {', '.join(sorted(self.wildcard_ips))}")
        else:
            good("no wildcard DNS")

    def resolve_all(self) -> None:
        step("DNS resolution")
        pending = [s for s in self.results.values() if not s.resolved]
        if not pending:
            info("nothing left to resolve")
            return

        prog = Progress(len(pending), "resolve")
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.args.threads) as pool:
                futures = {pool.submit(resolve, s.host, 5.0): s for s in pending}
                for fut in concurrent.futures.as_completed(futures):
                    sub = futures[fut]
                    prog.tick()
                    if _INTERRUPTED.is_set():
                        break
                    try:
                        sub.ips = fut.result()
                    except Exception:  # noqa: BLE001
                        sub.ips = []
                    sub.resolved = bool(sub.ips)
                    if not sub.resolved:
                        sub.reason = "does not resolve (NXDOMAIN)"
        except KeyboardInterrupt:
            _INTERRUPTED.set()
        finally:
            prog.close()

        r = sum(1 for s in self.results.values() if s.resolved)
        good(f"{r}/{len(self.results)} resolve to an IP")

    def probe_all(self) -> None:
        step("HTTP probing")
        targets = [s for s in self.results.values() if s.resolved]
        if not targets:
            warn("nothing resolved, nothing to probe")
            return

        schemes = ["https", "http"]
        prog = Progress(len(targets), "probe")
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.args.threads) as pool:
                futures = {
                    pool.submit(probe_http, s.host, self.args.http_timeout, schemes): s
                    for s in targets
                }
                for fut in concurrent.futures.as_completed(futures):
                    sub = futures[fut]
                    prog.tick()
                    if _INTERRUPTED.is_set():
                        break
                    try:
                        alive, code, url, title = fut.result()
                    except Exception:  # noqa: BLE001
                        alive, code, url, title = False, None, None, None
                    sub.alive = alive
                    sub.status_code = code
                    sub.url = url
                    sub.title = title
                    if not alive:
                        sub.reason = "resolves but no HTTP/HTTPS response"
        except KeyboardInterrupt:
            _INTERRUPTED.set()
        finally:
            prog.close()

        a = sum(1 for s in self.results.values() if s.alive)
        good(f"{a} host(s) answered on HTTP/HTTPS")

    # -- fingerprinting (techfinger module) --------------------------------- #

    def fingerprint_all(self) -> None:
        """Phase 1-3 tech fingerprinting on every live host.

        Fully optional and self-contained: if the techfinger package is missing
        or errors, the scan is unaffected - we warn and move on, exactly like a
        failed enumeration source.
        """
        step("Technology fingerprinting")
        targets = self.live
        if not targets:
            warn("no live hosts to fingerprint")
            return

        try:
            import techfinger
            from techfinger import report as tf_report
        except Exception as e:  # noqa: BLE001
            error(f"techfinger module unavailable: {e}")
            info("the core scan is unaffected; fingerprinting skipped")
            return

        online = not self.args.offline_intel
        info(f"fingerprinting {len(targets)} host(s)"
             f"{'' if online else ' (offline: no CVE/EOL lookup)'}")

        prog = Progress(len(targets), "fingerprint")
        fps = []
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(self.args.threads, 20)) as pool:
                futures = {
                    pool.submit(
                        techfinger.fingerprint_and_enrich,
                        s.host,
                        timeout=self.args.http_timeout,
                        url=s.url,
                        online=online,
                    ): s
                    for s in targets
                }
                for fut in concurrent.futures.as_completed(futures):
                    sub = futures[fut]
                    prog.tick()
                    if _INTERRUPTED.is_set():
                        break
                    try:
                        fp = fut.result()
                    except Exception as e:  # noqa: BLE001
                        warn(f"{sub.host}: fingerprint failed: {e}")
                        continue
                    fps.append(fp)
        except KeyboardInterrupt:
            _INTERRUPTED.set()
        finally:
            prog.close()

        # Sort to match the live-host ordering.
        fps.sort(key=lambda f: f.host)
        self.fingerprints = fps

        n_tech = sum(len(f.technologies) for f in fps)
        n_cve = sum(len(t.vulnerabilities) for f in fps for t in f.technologies)
        n_eol = sum(1 for f in fps for t in f.technologies if t.end_of_life)
        good(f"{n_tech} technologies, {n_cve} CVEs, {n_eol} EOL across {len(fps)} host(s)")

        if not _QUIET:
            for fp in fps:
                try:
                    tf_report.render_console(fp, C=C, out=out)
                except _PipeClosed:
                    raise
                except Exception as e:  # noqa: BLE001 - printing must not lose data
                    warn(f"could not render {fp.host} to console: {e}")

    # -- reporting ---------------------------------------------------------- #

    @property
    def live(self) -> list[Subdomain]:
        return sorted((s for s in self.results.values() if s.alive), key=lambda s: s.host)

    @property
    def dead(self) -> list[Subdomain]:
        return sorted((s for s in self.results.values() if not s.alive), key=lambda s: s.host)

    def report(self) -> None:
        live, dead = self.live, self.dead
        total = len(self.results)

        out(f"\n{C.BOLD}{'=' * 72}{C.RESET}")
        out(f"{C.BOLD}  RESULTS for {C.CYAN}{self.domain}{C.RESET}")
        out(f"{C.BOLD}{'=' * 72}{C.RESET}\n")

        if live:
            out(f"{C.GREEN}{C.BOLD}  LIVE ({len(live)}){C.RESET}\n")
            for s in live:
                code = s.status_code
                if code is None:
                    badge = f"{C.YELLOW}TLS{C.RESET}"
                elif 200 <= code < 300:
                    badge = f"{C.GREEN}{code}{C.RESET}"
                elif 300 <= code < 400:
                    badge = f"{C.CYAN}{code}{C.RESET}"
                elif 400 <= code < 500:
                    badge = f"{C.YELLOW}{code}{C.RESET}"
                else:
                    badge = f"{C.RED}{code}{C.RESET}"
                ip = s.ips[0] if s.ips else "-"
                title = f"  {C.DIM}{s.title}{C.RESET}" if s.title else ""
                out(f"    [{badge}] {s.host:<42} {C.DIM}{ip}{C.RESET}{title}")

        if dead and not self.args.no_dead:
            out(f"\n{C.RED}{C.BOLD}  DEAD ({len(dead)}){C.RESET}\n")
            for s in dead:
                mark = "no-dns" if not s.resolved else "no-http"
                out(f"    [{C.RED}{mark:^6}{C.RESET}] {s.host:<42} {C.DIM}{s.reason}{C.RESET}")

        elapsed = (datetime.now(timezone.utc) - self.started).total_seconds()
        out(f"\n{C.BOLD}{'-' * 72}{C.RESET}")
        out(
            f"  total {C.BOLD}{total}{C.RESET}  ·  "
            f"live {C.GREEN}{C.BOLD}{len(live)}{C.RESET}  ·  "
            f"dead {C.RED}{C.BOLD}{len(dead)}{C.RESET}  ·  "
            f"{elapsed:.1f}s"
        )
        out(f"{C.BOLD}{'-' * 72}{C.RESET}\n")

    def save(self) -> None:
        out = Path(self.args.output) if self.args.output else Path(f"subhunter_{self.domain}")
        try:
            out.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            error(f"cannot create output dir {out}: {e}")
            return

        files = {
            "all.txt": [s.host for s in sorted(self.results.values(), key=lambda x: x.host)],
            "live.txt": [s.host for s in self.live],
            "dead.txt": [s.host for s in self.dead],
            "live_urls.txt": [s.url for s in self.live if s.url],
        }
        written: list[str] = []
        for name, lines in files.items():
            try:
                (out / name).write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
                written.append(name)
            except OSError as e:
                error(f"failed writing {name}: {e}")

        report = {
            "tool": "SubHunter",
            "version": __version__,
            "author": __author__,
            "domain": self.domain,
            "started": self.started.isoformat(),
            "finished": datetime.now(timezone.utc).isoformat(),
            "wildcard_ips": sorted(self.wildcard_ips),
            "summary": {
                "total": len(self.results),
                "live": len(self.live),
                "dead": len(self.dead),
            },
            "sources": [asdict(t) for t in self.tool_results],
            "subdomains": [s.to_dict() for s in sorted(self.results.values(), key=lambda x: x.host)],
        }
        try:
            (out / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
            written.append("report.json")
        except (OSError, TypeError, ValueError) as e:
            error(f"failed writing report.json: {e}")

        # Fingerprint reports, when the module ran.
        if self.fingerprints:
            try:
                from techfinger import report as tf_report

                tf_report.write_json(self.fingerprints, out / "techfinger.json", self.domain)
                written.append("techfinger.json")
                (out / "techfinger.txt").write_text(
                    tf_report.render_text(self.fingerprints, self.domain), encoding="utf-8"
                )
                written.append("techfinger.txt")
            except Exception as e:  # noqa: BLE001
                error(f"failed writing techfinger reports: {e}")

        if written:
            good(f"saved {', '.join(written)} -> {C.BOLD}{out}/{C.RESET}")

    def run(self) -> int:
        self.check_wildcard()

        if not self.args.brute_only:
            self.enumerate_passive()
        if self.args.brute or self.args.brute_only:
            self.enumerate_brute()

        if not self.results:
            warn("no subdomains discovered")
            warn("install more tools (subfinder, assetfinder, findomain) or try --brute")
            return 1

        self.resolve_all()
        if not self.args.no_probe:
            self.probe_all()
        else:
            # Without probing, "live" just means it resolves.
            for s in self.results.values():
                s.alive = s.resolved
                if not s.alive:
                    s.reason = "does not resolve (NXDOMAIN)"

        if self.args.fingerprint:
            self.fingerprint_all()

        self.report()
        if not self.args.no_save:
            self.save()
        return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def check_environment() -> None:
    step("Environment")
    installed, absent = [], []
    for s in PASSIVE_SOURCES:
        if s.binary is None:
            continue
        (installed if s.available() else absent).append(s.name)
    if installed:
        good(f"installed: {', '.join(installed)}")
    if absent:
        warn(f"missing:   {', '.join(absent)}")
        info("install on Kali:  sudo apt install -y assetfinder findomain")
        info("or via go:        go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
    info("crt.sh + hackertarget always available (no install needed)")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="subhunter",
        description=f"SubHunter v{__version__} - subdomain enumeration and liveness triage by {__author__}",
        epilog=(
            "examples:\n"
            "  subhunter.py -d example.com\n"
            "  subhunter.py -d example.com --brute -t 100\n"
            "  subhunter.py -d example.com --fingerprint\n"
            "  subhunter.py -d example.com --exclude crt.sh --no-dead -o ./out\n"
            "  subhunter.py --check\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-d", "--domain", help="target domain, e.g. example.com")
    p.add_argument("-o", "--output", help="output directory (default: subhunter_<domain>)")
    p.add_argument("-t", "--threads", type=int, default=50, help="concurrent workers (default: 50)")
    p.add_argument("--timeout", type=int, default=300, help="per-tool timeout in seconds (default: 300)")
    p.add_argument("--http-timeout", type=float, default=8.0, help="HTTP probe timeout (default: 8)")
    p.add_argument("--brute", action="store_true", help="also brute force with a wordlist")
    p.add_argument("--brute-only", action="store_true", help="skip passive sources, brute force only")
    p.add_argument("-w", "--wordlist", help="wordlist for brute force")
    p.add_argument("--exclude", default="", help="comma-separated sources to skip, e.g. crt.sh,hackertarget")
    p.add_argument(
        "--insecure",
        action="store_true",
        help="skip TLS verification for passive API sources (use behind an intercepting proxy)",
    )
    p.add_argument("--no-probe", action="store_true", help="skip HTTP probing (DNS resolution only)")
    p.add_argument(
        "--fingerprint",
        "--fp",
        dest="fingerprint",
        action="store_true",
        help="fingerprint tech + look up CVEs/EOL on every live host (techfinger module)",
    )
    p.add_argument(
        "--offline-intel",
        action="store_true",
        help="with --fingerprint: skip online CVE/EOL lookups (Phase 1+2 only)",
    )
    p.add_argument("--no-dead", action="store_true", help="hide dead hosts from the report")
    p.add_argument("--no-save", action="store_true", help="do not write output files")
    p.add_argument("--no-banner", action="store_true", help="suppress the banner")
    p.add_argument("-q", "--quiet", action="store_true", help="only print the final report")
    p.add_argument("--no-color", action="store_true", help="disable coloured output")
    p.add_argument("--check", action="store_true", help="show which tools are installed and exit")
    p.add_argument("-v", "--version", action="version", version=f"SubHunter {__version__} by {__author__}")
    return p


def _handle_sigint(signum, frame) -> None:  # noqa: ARG001
    if _INTERRUPTED.is_set():
        error("force quit")
        os._exit(130)
    _INTERRUPTED.set()
    error("interrupted - finishing up, press Ctrl+C again to force quit")


def main(argv: list[str] | None = None) -> int:
    try:
        return _main(argv)
    except _PipeClosed:
        # Piped into `head` or similar. Point stdout at devnull so the
        # interpreter's exit-time flush doesn't re-raise on the dead pipe.
        _silence_stdout()
        return 0


def _silence_stdout() -> None:
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
    except Exception:  # noqa: BLE001
        pass


def _main(argv: list[str] | None = None) -> int:
    global _QUIET

    parser = build_parser()
    args = parser.parse_args(argv)

    _init_colours(force=False)
    if args.no_color:
        C.disable()
    _QUIET = args.quiet

    if not args.no_banner and not args.quiet:
        print_banner()

    if args.check:
        check_environment()
        return 0

    if not args.domain:
        parser.print_help()
        error("\na domain is required: -d example.com")
        return 2

    try:
        args.domain = normalise_domain(args.domain)
    except DomainError as e:
        error(f"invalid domain: {e}")
        return 2

    # Clamp the knobs rather than letting people footgun themselves.
    if args.threads < 1:
        warn("threads must be >= 1, using 1")
        args.threads = 1
    elif args.threads > 500:
        warn("threads capped at 500")
        args.threads = 500
    if args.timeout < 10:
        warn("timeout must be >= 10s, using 10")
        args.timeout = 10
    if args.http_timeout < 1:
        args.http_timeout = 1.0

    args.exclude = {e.strip().lower() for e in args.exclude.split(",") if e.strip()}
    if args.brute_only:
        args.brute = True

    if args.insecure:
        set_api_ssl_insecure()
        warn("TLS verification disabled for passive API sources")

    signal.signal(signal.SIGINT, _handle_sigint)

    info(f"target: {C.BOLD}{args.domain}{C.RESET}")

    try:
        return SubHunter(args).run()
    except KeyboardInterrupt:
        error("aborted by user")
        return 130
    except _PipeClosed:
        raise  # handled by main(); not a real failure
    except Exception as e:  # noqa: BLE001 - last line of defence
        error(f"fatal: {type(e).__name__}: {e}")
        if os.environ.get("SUBHUNTER_DEBUG"):
            import traceback

            traceback.print_exc()
        else:
            info("set SUBHUNTER_DEBUG=1 for a traceback")
        return 1


if __name__ == "__main__":
    sys.exit(main())
