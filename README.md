# savaid-tools

**Bug bounty & recon toolkit — one repo, many tools.**

A growing collection of offensive-security and reconnaissance tools written in
pure Python (stdlib only, zero dependencies).

---

## 🛠 Tools

### SubHunter — Subdomain Enumeration & Liveness Triage

Point it at a domain. It runs every enumeration tool you have installed, merges
the results, checks what actually resolves, probes what actually answers, and
splits the lot into **live** and **dead**.

```
   _____       _     _   _             _
  / ____|     | |   | | | |           | |
 | (___  _   _| |__ | |_| |_   _ _ __ | |_ ___ _ __
  \___ \| | | | '_ \|  _  | | | | '_ \| __/ _ \ '__|
  ____) | |_| | |_) | | | | |_| | | | | ||  __/ |
 |_____/ \__,_|_.__/|_| |_|\__,_|_| |_|\__\___|_|
```

#### Features

- **Runs your tools in parallel** — subfinder, assetfinder, findomain
- **Works with zero tools installed** — crt.sh and hackertarget need nothing but network
- **Brute force** with SecLists auto-detection, plus a built-in fallback wordlist
- **Wildcard DNS detection** so brute force doesn't hand you 5,000 false positives
- **Live/dead split** — DNS resolution, then a real HTTP/HTTPS probe with status codes and page titles
- **Never crashes on one bad source** — every tool is optional and every failure is contained
- **Output you can pipe** — `all.txt`, `live.txt`, `dead.txt`, `live_urls.txt`, `report.json`

### Takeover Check — Subdomain Takeover Reconnaissance

Reads a list of dead subdomains and gathers evidence for takeover analysis —
CNAME chain, provider identification, HTTP fingerprints — so you can make the call.

### TechFinger — Technology Fingerprinting & Security Intelligence

Runs over every **live** subdomain and answers "what is this, and is it
vulnerable?". Three phases per host:

- **Phase 1 – Fingerprinting**: web server, language, framework, CMS, JS/CSS
  libraries, CDN, WAF, reverse proxy, API/analytics/auth tech, TLS, and security
  headers — each with a **confidence score and the evidence** that produced it,
  gathered from multiple techniques (headers, cookies, HTML/meta, script `src`,
  TLS).
- **Phase 2 – Version validation**: when several techniques report a version,
  the strongest wins and agreement boosts confidence — never a single weak guess
  when stronger evidence exists.
- **Phase 3 – Security intelligence**: for each `(technology, version)` it looks
  up **CVEs, CVSS, severity** (NVD), **End-of-Life** status (endoflife.date),
  **public-exploit / Metasploit** availability (CISA KEV + references), and a
  **recommended fixed version**.

Runs inline in a scan via `--fingerprint`, or standalone via `fingerprint.py`
against any `live.txt`. Stdlib-only; online lookups are cached and degrade
gracefully to "unknown" with no network. Set `NVD_API_KEY` for a higher CVE rate
limit (optional).

---

## Install

Python 3.9+ required. No pip packages — standard library only.

```bash
git clone https://github.com/Savaid-Khan-Official/savaid-tools.git
cd savaid-tools
chmod +x subhunter.py takeover_check.py
```

> On Kali/Parrot, install optional tools for better coverage:

```bash
sudo apt install -y assetfinder findomain
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

Check what you've got:

```bash
./subhunter.py --check
```

## Usage

```bash
# Standard run
./subhunter.py -d example.com

# Add brute force, more threads
./subhunter.py -d example.com --brute -t 100

# Brute force only, custom wordlist
./subhunter.py -d example.com --brute-only -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt

# Skip a slow source, hide dead hosts, choose output dir
./subhunter.py -d example.com --exclude amass --no-dead -o ./recon

# DNS only, no HTTP probing
./subhunter.py -d example.com --no-probe

# Pipe-friendly
./subhunter.py -d example.com -q --no-color | tee scan.log
```

### Options

| Flag | Description |
|---|---|
| `-d, --domain` | Target domain |
| `-o, --output` | Output directory (default `subhunter_<domain>`) |
| `-t, --threads` | Concurrent workers (default 50, max 500) |
| `--timeout` | Per-tool timeout in seconds (default 300) |
| `--http-timeout` | HTTP probe timeout (default 8) |
| `--brute` | Also brute force with a wordlist |
| `--brute-only` | Skip passive sources entirely |
| `-w, --wordlist` | Wordlist for brute force |
| `--exclude` | Comma-separated sources to skip, e.g. `amass,crt.sh` |
| `--insecure` | Skip TLS verification for API sources (for intercepting proxies) |
| `--no-probe` | Skip HTTP probing, DNS only |
| `--no-dead` | Hide dead hosts from the report |
| `--no-save` | Don't write output files |
| `-q, --quiet` | Only print the final report |
| `--no-color` | Disable colour |
| `--check` | Show which tools are installed and exit |

## Output

```
========================================================================
  RESULTS for github.com
========================================================================

  LIVE (90)

    [200] api.github.com                    20.207.73.85
    [200] accessibility.github.com          2606:50c0:8000::153  GitHub Accessibility
    [301] blog.github.com                   2606:50c0:8001::153
    [503] atom-installer.github.com         185.199.111.133

  DEAD (56)

    [no-dns] www.visualstudio.github.com    does not resolve (NXDOMAIN)
    [no-http] some.github.com               resolves but no HTTP/HTTPS response

------------------------------------------------------------------------
  total 151  ·  live 95  ·  dead 56  ·  45.2s
------------------------------------------------------------------------
```

**Live** means a server answered on HTTP or HTTPS — including 4xx and 5xx,
because a 403 is still an asset worth knowing about. **Dead** splits into
`no-dns` (doesn't resolve) and `no-http` (resolves, but nothing listening).

`report.json` carries everything: per-host sources, IPs, status codes, titles,
and per-source stats.

## Takeover check

`takeover_check.py` is a companion tool. Feed it the `dead.txt` a scan produced
(or any list of dead subdomains, one per line) and it gathers everything needed
to judge a **subdomain takeover** into a single report — designed to be handed
straight to an AI for a final verdict.

For each host it collects: the full `dig` CNAME chain, the raw CNAME target on
its own `CNAME_TARGET:` line, the inferred hosting provider, whether the chain
ends in NXDOMAIN, the HTTP status, the revealing headers (`Server` + `X-*`), and
the first 1000 characters of the body — where fingerprints like
*"There isn't a GitHub Pages site here"* live.

```bash
# Chain it straight off a scan
./subhunter.py -d example.com
./takeover_check.py -i subhunter_example.com/dead.txt -o takeover_report.txt

# Defaults to dead_subdomains.txt in the current dir
./takeover_check.py

# Large dead lists: go concurrent
./takeover_check.py -i dead.txt --threads 20
```

Needs `dig` (`sudo apt install -y dnsutils`); without it, it falls back to the
system resolver and says so in the report. It **collects evidence, it does not
decide** — one clearly delimited block per host, then you (or your AI) judge.

| Flag | Description |
|---|---|
| `-i, --input` | Dead-subdomain file, one per line (default `dead_subdomains.txt`) |
| `-o, --output` | Consolidated report (default `takeover_report.txt`) |
| `-t, --threads` | Concurrent workers (default 1 = sequential) |
| `--timeout` | Per-host timeout for dig and HTTP (default 10s) |

Each block looks like:

```
========================================
SUBDOMAIN: shop.example.com
========================================
CNAME_TARGET: mystore.myshopify.com
PROVIDER: Shopify
DIG_OUTPUT:
; hop 0: shop.example.com  (status: NOERROR)
shop.example.com. 300 IN CNAME mystore.myshopify.com.
; hop 1: mystore.myshopify.com  (status: NXDOMAIN)
NXDOMAIN: true
HTTP_STATUS: 404
HEADERS:
Server: nginx
RESPONSE_BODY (first 1000 chars):
<html>...Sorry, this shop is currently unavailable...</html>
========================================
```

At the end it prints a short triage summary to stderr — hosts that have both
NXDOMAIN **and** a known provider are flagged as the ones to review first.

## TechFinger (technology fingerprinting)

Fingerprint every live host and enrich it with CVE/EOL/exploit intelligence.
Runs inline in a scan, or standalone against any live list.

```bash
# Inline: fingerprint every live host during the scan
./subhunter.py -d example.com --fingerprint

# Fingerprint only, skip the online CVE/EOL lookups (Phase 1+2 only, fully offline)
./subhunter.py -d example.com --fingerprint --offline-intel

# Standalone, off a scan's live.txt (mirrors takeover_check.py)
./fingerprint.py -i subhunter_example.com/live.txt -o techfinger_report.txt

# Standalone with a JSON report and more threads
./fingerprint.py -i live.txt -j techfinger.json --threads 15
```

A scan run with `--fingerprint` adds two files to the output dir:
`techfinger.json` (full structured data) and `techfinger.txt` (one readable
block per host). The module is completely self-contained — if the `techfinger/`
package is absent or errors, the core scan is unaffected.

| Flag (`fingerprint.py`) | Description |
|---|---|
| `-i, --input` | Live-host file, one per line (default `live.txt`) |
| `-o, --output` | Consolidated text report (default `techfinger_report.txt`) |
| `-j, --json` | Also write a structured JSON report to this path |
| `-t, --threads` | Concurrent workers (default 10) |
| `--timeout` | Per-host HTTP/TLS timeout (default 10s) |
| `--offline` | Skip online CVE/EOL/exploit lookups (Phase 1+2 only) |

Each finding carries technology, version, confidence, evidence, CVEs, CVSS,
severity, EOL status, public-exploit and Metasploit availability, and a
recommended version. Every version is corroborated across techniques (Phase 2)
before it's trusted, and every CVE comes from **live NVD data** — nothing is
fabricated. Set the optional `NVD_API_KEY` env var for a higher rate limit.

A text block looks like:

```
============================================================
HOST: shop.example.com
URL: https://shop.example.com
STATUS: 200
============================================================
SECURITY_HEADER_GRADE: C
MISSING_SECURITY_HEADERS: Content-Security-Policy, Permissions-Policy
TLS: TLSv1.3 issuer=Let's Encrypt verified=True

TECHNOLOGIES:
  - nginx  [web-server]  version=1.18.0  confidence=90%
      evidence(header, 75%): Server: nginx/1.18.0
      version_candidates: header=1.18.0
      end_of_life: True  (cycle 1.18 reached EOL (2021-04-20))
      recommended_version: 1.18.0
      CVEs (4):
        CVE-2021-23017  CVSS=7.7  HIGH  PUBLIC-EXPLOIT
        CVE-2023-44487  CVSS=7.5  HIGH  PUBLIC-EXPLOIT
```

The `techfinger/` package is modular by design: add a technology by dropping one
entry into [`techfinger/fingerprints.py`](techfinger/fingerprints.py) — no engine
change required, the same "table you extend, not code you edit" pattern used by
the takeover module's provider list.

## Notes

- **crt.sh is flaky.** It 502s and rate-limits regularly. SubHunter reports it
  and carries on with the other sources.
- **Behind a corporate/intercepting proxy?** TLS verification will fail for the
  API sources. Use `--insecure`.
- **Wildcard domains** are detected up front; matching brute-force hits are
  dropped as false positives.
- **Ctrl+C** once for a graceful finish with partial results, twice to force quit.

## Roadmap (v2)

- ~~Technology fingerprinting with CVE/EOL/exploit intelligence~~ ✅ shipped (TechFinger)
- Port scanning and service detection
- Screenshots of live hosts
- `httpx` / `dnsx` / `puredns` integration when installed
- API keys for SecurityTrails, Shodan, VirusTotal, Censys
- Recursive enumeration and permutation scanning
- HTML report
- Wider fingerprint coverage + a bundled fingerprint DB for automated takeover
  verdicts (currently the takeover module leaves the final call to you / your AI)

## Legal

Only scan what you own or have written permission to test. Unauthorised
scanning is illegal in most jurisdictions. This is for authorised security
assessment and education — you're responsible for how you use it.

## License

MIT — see [LICENSE](LICENSE).
