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

## Notes

- **crt.sh is flaky.** It 502s and rate-limits regularly. SubHunter reports it
  and carries on with the other sources.
- **Behind a corporate/intercepting proxy?** TLS verification will fail for the
  API sources. Use `--insecure`.
- **Wildcard domains** are detected up front; matching brute-force hits are
  dropped as false positives.
- **Ctrl+C** once for a graceful finish with partial results, twice to force quit.

## Roadmap (v2)

- Port scanning and service detection
- Screenshots of live hosts
- `httpx` / `dnsx` / `puredns` integration when installed
- API keys for SecurityTrails, Shodan, VirusTotal, Censys
- Recursive enumeration and permutation scanning
- HTML report
- Bundled fingerprint database for automated takeover verdicts (currently the
  takeover module leaves the final call to you / your AI)

## Legal

Only scan what you own or have written permission to test. Unauthorised
scanning is illegal in most jurisdictions. This is for authorised security
assessment and education — you're responsible for how you use it.

## License

MIT — see [LICENSE](LICENSE).
