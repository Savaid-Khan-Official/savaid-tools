#!/usr/bin/env bash
#
# install_tools.sh - installs every optional external tool used by this repo.
#
# savaid-tools (subhunter.py, takeover_check.py, fingerprint.py) is pure
# Python stdlib - it needs NO pip packages and works with zero tools
# installed. This script only fetches the OPTIONAL binaries that make
# SubHunter's coverage better and takeover_check.py's CNAME chain more
# accurate:
#
#   subfinder    - passive subdomain enumeration (installed via `go install`)
#   assetfinder  - passive subdomain enumeration (apt, falls back to go install)
#   findomain    - passive subdomain enumeration (apt, falls back to GitHub release)
#   dig          - CNAME chain walking for takeover_check.py (package: dnsutils)
#   seclists     - optional, larger wordlist for `--brute` (skipped with --minimal)
#
# Target: Debian-family Linux (Kali, Parrot, Ubuntu, Debian). Designed to be
# safe to re-run - every step is independent and a failure in one tool does
# not stop the others, mirroring this repo's own "never crash on one bad
# source" philosophy.
#
# Usage:
#   chmod +x install_tools.sh
#   ./install_tools.sh              # install everything
#   ./install_tools.sh --minimal    # skip seclists (it's large)
#   ./install_tools.sh --check      # only show what's installed, install nothing
#
set -uo pipefail

# --------------------------------------------------------------------------- #
# Output helpers
# --------------------------------------------------------------------------- #

if [ -t 1 ]; then
    C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
    C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_CYAN=$'\033[36m'
else
    C_RESET=""; C_BOLD=""; C_DIM=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_CYAN=""
fi

info() { printf '%s[*]%s %s\n' "$C_CYAN" "$C_RESET" "$1"; }
good() { printf '%s[+]%s %s\n' "$C_GREEN" "$C_RESET" "$1"; }
warn() { printf '%s[!]%s %s\n' "$C_YELLOW" "$C_RESET" "$1"; }
err()  { printf '%s[-]%s %s\n' "$C_RED" "$C_RESET" "$1" >&2; }
step() { printf '\n%s==>%s %s%s%s\n' "$C_BOLD$C_CYAN" "$C_RESET" "$C_BOLD" "$1" "$C_RESET"; }

# --------------------------------------------------------------------------- #
# Args
# --------------------------------------------------------------------------- #

MINIMAL=0
CHECK_ONLY=0
for arg in "$@"; do
    case "$arg" in
        --minimal) MINIMAL=1 ;;
        --check) CHECK_ONLY=1 ;;
        -h|--help)
            echo "Usage: $0 [--minimal] [--check]"
            echo "  --minimal   skip the optional SecLists wordlist (large download)"
            echo "  --check     only report what's installed, install nothing"
            exit 0
            ;;
        *) warn "unknown argument: $arg" ;;
    esac
done

# --------------------------------------------------------------------------- #
# Environment checks
# --------------------------------------------------------------------------- #

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GOPATH_DIR="$(command -v go >/dev/null 2>&1 && go env GOPATH 2>/dev/null)"
GOBIN_DIR="${GOPATH_DIR:-$HOME/go}/bin"
export PATH="$PATH:$GOBIN_DIR:/usr/local/go/bin"

have() { command -v "$1" >/dev/null 2>&1; }

report_status() {
    step "Current status"
    for bin in python3 dig subfinder assetfinder findomain go apt-get; do
        if have "$bin"; then
            good "$(printf '%-12s' "$bin") installed  ($(command -v "$bin"))"
        else
            warn "$(printf '%-12s' "$bin") not found"
        fi
    done
    if [ -d /usr/share/seclists/Discovery/DNS ]; then
        good "seclists     installed  (/usr/share/seclists)"
    else
        warn "seclists     not found (subhunter falls back to its built-in wordlist)"
    fi
}

if [ "$CHECK_ONLY" -eq 1 ]; then
    report_status
    echo
    info "run without --check to install what's missing"
    exit 0
fi

step "savaid-tools dependency installer"
info "repo: $REPO_DIR"

if ! have python3; then
    err "python3 not found - install Python 3.9+ first (this repo is stdlib-only, no pip packages needed)"
    exit 1
fi
PY_VER="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
good "python3 $PY_VER found (only the stdlib is required - no pip installs)"

if ! have apt-get; then
    err "apt-get not found. This script targets Debian-family Linux (Kali/Parrot/Ubuntu/Debian)."
    err "On another distro, install manually: dnsutils/bind-tools (dig), plus subfinder/assetfinder/findomain from their GitHub releases."
    exit 1
fi

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if have sudo; then
        SUDO="sudo"
    else
        err "not root and 'sudo' is unavailable - re-run as root or install sudo"
        exit 1
    fi
fi

APT_UPDATED=0
apt_update_once() {
    if [ "$APT_UPDATED" -eq 0 ]; then
        info "apt-get update"
        if $SUDO apt-get update -qq; then
            APT_UPDATED=1
        else
            warn "apt-get update failed - continuing with existing package lists"
        fi
    fi
}

apt_install() {
    apt_update_once
    info "apt-get install -y $*"
    if $SUDO apt-get install -y "$@"; then
        return 0
    fi
    return 1
}

# --------------------------------------------------------------------------- #
# dig (dnsutils) - required by takeover_check.py's CNAME chain walk
# --------------------------------------------------------------------------- #

step "dig (for takeover_check.py)"
if have dig; then
    good "dig already installed"
else
    if apt_install dnsutils; then
        good "dnsutils installed"
    else
        err "failed to install dnsutils - takeover_check.py will fall back to the system resolver"
    fi
fi

# --------------------------------------------------------------------------- #
# assetfinder - passive source used by subhunter.py
# --------------------------------------------------------------------------- #

step "assetfinder (passive subdomain source)"
if have assetfinder; then
    good "assetfinder already installed"
elif apt_install assetfinder; then
    good "assetfinder installed via apt"
else
    warn "assetfinder not in apt repos here - trying 'go install'"
    if ! have go; then
        info "go not found, installing golang-go"
        apt_install golang-go || warn "could not install golang-go"
    fi
    if have go; then
        if go install github.com/tomnomnom/assetfinder@latest; then
            good "assetfinder installed via go install -> $GOBIN_DIR"
        else
            err "go install assetfinder failed"
        fi
    else
        err "no go toolchain available - skipping assetfinder (subhunter.py still works without it)"
    fi
fi

# --------------------------------------------------------------------------- #
# findomain - passive source used by subhunter.py
# --------------------------------------------------------------------------- #

step "findomain (passive subdomain source)"
if have findomain; then
    good "findomain already installed"
elif apt_install findomain; then
    good "findomain installed via apt"
else
    warn "findomain not in apt repos here - fetching prebuilt Linux binary from GitHub releases"
    TMP_BIN="$(mktemp -d)/findomain"
    if have curl; then
        DL="curl -fsSL -o"
    elif have wget; then
        DL="wget -q -O"
    else
        DL=""
    fi
    if [ -n "$DL" ]; then
        if $DL "$TMP_BIN" "https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux"; then
            chmod +x "$TMP_BIN"
            if $SUDO mv "$TMP_BIN" /usr/local/bin/findomain; then
                good "findomain installed to /usr/local/bin/findomain"
            else
                err "could not move findomain into /usr/local/bin - binary left at $TMP_BIN"
            fi
        else
            err "failed to download findomain release binary"
        fi
    else
        err "neither curl nor wget available - skipping findomain (subhunter.py still works without it)"
    fi
fi

# --------------------------------------------------------------------------- #
# subfinder - passive source used by subhunter.py (Go tool, no apt package)
# --------------------------------------------------------------------------- #

step "subfinder (passive subdomain source)"
if have subfinder; then
    good "subfinder already installed"
else
    if ! have go; then
        info "go not found, installing golang-go"
        apt_install golang-go || warn "could not install golang-go"
    fi
    if have go; then
        if go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest; then
            good "subfinder installed via go install -> $GOBIN_DIR"
        else
            err "go install subfinder failed"
        fi
    else
        err "no go toolchain available - skipping subfinder (subhunter.py still works without it)"
    fi
fi

# --------------------------------------------------------------------------- #
# seclists - optional, bigger --brute wordlist (subhunter.py auto-detects it)
# --------------------------------------------------------------------------- #

if [ "$MINIMAL" -eq 1 ]; then
    step "seclists (skipped: --minimal)"
else
    step "seclists (optional --brute wordlist)"
    if [ -d /usr/share/seclists/Discovery/DNS ]; then
        good "seclists already installed"
    elif apt_install seclists; then
        good "seclists installed"
    else
        warn "seclists not available via apt here - subhunter.py falls back to its built-in wordlist for --brute"
        info "install manually: git clone https://github.com/danielmiessler/SecLists /usr/share/seclists"
    fi
fi

# --------------------------------------------------------------------------- #
# Make the repo's scripts executable
# --------------------------------------------------------------------------- #

step "Permissions"
for f in subhunter.py takeover_check.py fingerprint.py; do
    if [ -f "$REPO_DIR/$f" ]; then
        chmod +x "$REPO_DIR/$f"
        good "chmod +x $f"
    fi
done

# --------------------------------------------------------------------------- #
# Final report
# --------------------------------------------------------------------------- #

report_status

if [[ ":$PATH:" != *":$GOBIN_DIR:"* ]] || ! grep -q "$GOBIN_DIR" "$HOME/.bashrc" 2>/dev/null; then
    step "PATH"
    warn "Go-installed tools live in $GOBIN_DIR"
    info "add this to your ~/.bashrc (or ~/.zshrc) so it's available in new shells:"
    echo "    export PATH=\"\$PATH:$GOBIN_DIR\""
fi

step "Done"
info "verify everything subhunter.py can see with:"
echo "    ./subhunter.py --check"
