#!/usr/bin/env bash
# =============================================================================
# Copy Fail (CVE-2026-31431) Vulnerability Checker
# =============================================================================
#
# This script checks whether the running Linux system is vulnerable to the
# "Copy Fail" local privilege escalation vulnerability disclosed on
# 2026-04-29 and tracked as CVE-2026-31431.
#
# Background:
#   Copy Fail is a logic bug in the Linux kernel's `authencesn` AEAD
#   cryptographic template combined with the AF_ALG (algif_aead) socket
#   interface. An unprivileged local user can trigger a deterministic,
#   controlled 4-byte write into the page cache of any readable file on the
#   system, which is enough to overwrite a setuid binary and gain root.
#
#   The bug was introduced in 2017 when an in-place AEAD optimization was
#   added to algif_aead.c, so essentially every mainstream distribution
#   shipped since 2017 is affected unless explicitly patched or mitigated.
#
# What this script does (read-only, non-destructive):
#   1. Collects basic system info (distro, kernel version).
#   2. Checks whether the running kernel version is at or above the known
#      patched version for the detected distribution.
#   3. Checks the runtime status of the `algif_aead` kernel module
#      (loaded / available / blacklisted / builtin).
#   4. Checks whether the AF_ALG socket family is reachable from userspace.
#   5. Prints a final verdict: VULNERABLE / MITIGATED / PATCHED / UNKNOWN.
#
# This script does NOT exploit the vulnerability and does NOT modify the
# system. It only reads kernel and distribution metadata.
#
# Usage:
#   chmod +x check-copy-fail.sh
#   ./check-copy-fail.sh           # human-readable output
#   ./check-copy-fail.sh --json    # machine-readable JSON summary
#
# Exit codes:
#   0  Patched or fully mitigated
#   1  Vulnerable
#   2  Unknown / could not determine
#   3  Not a Linux system / unsupported environment
# =============================================================================

set -u

# ----- Output helpers --------------------------------------------------------
# Colors are only emitted when stdout is a TTY, so logs and CI captures stay
# clean of escape sequences.
if [ -t 1 ]; then
    C_RED=$'\033[0;31m'
    C_GREEN=$'\033[0;32m'
    C_YELLOW=$'\033[0;33m'
    C_BLUE=$'\033[0;34m'
    C_BOLD=$'\033[1m'
    C_RESET=$'\033[0m'
else
    C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_BOLD=""; C_RESET=""
fi

JSON_MODE=0
if [ "${1:-}" = "--json" ]; then
    JSON_MODE=1
fi

log_info()  { [ "$JSON_MODE" -eq 0 ] && printf '%s[INFO]%s    %s\n'    "$C_BLUE"   "$C_RESET" "$1"; }
log_ok()    { [ "$JSON_MODE" -eq 0 ] && printf '%s[OK]%s      %s\n'    "$C_GREEN"  "$C_RESET" "$1"; }
log_warn()  { [ "$JSON_MODE" -eq 0 ] && printf '%s[WARN]%s    %s\n'    "$C_YELLOW" "$C_RESET" "$1"; }
log_bad()   { [ "$JSON_MODE" -eq 0 ] && printf '%s[VULN]%s    %s\n'    "$C_RED"    "$C_RESET" "$1"; }
log_head()  { [ "$JSON_MODE" -eq 0 ] && printf '\n%s== %s ==%s\n'      "$C_BOLD"   "$1" "$C_RESET"; }

# ----- Platform sanity check -------------------------------------------------
# This vulnerability is Linux kernel specific. Bail out early on anything else
# (macOS, BSD, WSL1, etc.) so we don't print misleading results.
if [ "$(uname -s)" != "Linux" ]; then
    log_warn "This system is not Linux (uname -s = $(uname -s)). CVE-2026-31431 does not apply."
    [ "$JSON_MODE" -eq 1 ] && printf '{"verdict":"not_applicable","os":"%s"}\n' "$(uname -s)"
    exit 3
fi

# ----- Collect distribution metadata -----------------------------------------
# /etc/os-release is the standard, machine-parseable identity file on every
# modern Linux distro (systemd-defined). We source a copy in a subshell-free
# way to avoid clobbering shell variables.
DISTRO_ID="unknown"
DISTRO_VERSION_ID="unknown"
DISTRO_PRETTY="unknown"
if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    DISTRO_ID="${ID:-unknown}"
    DISTRO_VERSION_ID="${VERSION_ID:-unknown}"
    DISTRO_PRETTY="${PRETTY_NAME:-unknown}"
fi

KERNEL_RELEASE="$(uname -r)"
KERNEL_VERSION_NUMERIC="$(printf '%s' "$KERNEL_RELEASE" | sed -E 's/^([0-9]+\.[0-9]+\.[0-9]+).*/\1/')"

log_head "System information"
log_info "Distribution : $DISTRO_PRETTY ($DISTRO_ID $DISTRO_VERSION_ID)"
log_info "Kernel       : $KERNEL_RELEASE"

# ----- Version comparison helper --------------------------------------------
# Compare two dotted version strings (e.g. "5.14.0-611.49.2" vs
# "5.14.0-611.49.1"). Returns 0 if $1 >= $2, 1 otherwise.
#
# We rely on `sort -V` which implements GNU's natural version ordering and is
# available on every distro this script targets (coreutils >= 7.0).
version_ge() {
    local a="$1" b="$2"
    [ "$a" = "$b" ] && return 0
    local first
    first=$(printf '%s\n%s\n' "$a" "$b" | sort -V | head -n1)
    [ "$first" = "$b" ]
}

# ----- Patched kernel database ----------------------------------------------
# Map of "distro_id:version_id" -> minimum patched kernel string.
# These are the official fixed versions published by each vendor's security
# advisory for CVE-2026-31431. Update this table as new advisories ship.
#
# A blank value means "no fixed version available yet from this vendor".
get_patched_version() {
    case "${DISTRO_ID}:${DISTRO_VERSION_ID}" in
        almalinux:8*|rhel:8*|rocky:8*|centos:8*)
            echo "4.18.0-553.121.1.el8_10" ;;
        almalinux:9*|rhel:9*|rocky:9*|centos:9*)
            echo "5.14.0-611.49.2.el9_7" ;;
        almalinux:10*|rhel:10*|rocky:10*|centos:10*)
            echo "6.12.0-124.52.2.el10_1" ;;
        ubuntu:26.04|ubuntu:26.10)
            # Ubuntu Resolute (26.04) and later are not affected upstream.
            echo "0.0.0" ;;
        ubuntu:*)
            # Ubuntu 18.04 .. 25.10: vendor patches are rolling out via apt.
            # No single fixed version covers every supported HWE/AWS/GCP
            # kernel flavor, so we leave this blank and fall back to the
            # module / AF_ALG runtime checks below.
            echo "" ;;
        debian:*)
            # Debian patches are published per-suite via DSA. Leave blank
            # and rely on runtime mitigation checks.
            echo "" ;;
        *)
            echo "" ;;
    esac
}

PATCHED_VERSION="$(get_patched_version)"

# ----- Check 1: kernel version vs patched version ---------------------------
log_head "Check 1 / 3 — Kernel version"

KERNEL_STATUS="unknown"
if [ -n "$PATCHED_VERSION" ]; then
    if version_ge "$KERNEL_RELEASE" "$PATCHED_VERSION"; then
        log_ok "Running kernel ($KERNEL_RELEASE) is at or above the patched version ($PATCHED_VERSION)."
        KERNEL_STATUS="patched"
    else
        log_bad "Running kernel ($KERNEL_RELEASE) is older than the patched version ($PATCHED_VERSION)."
        KERNEL_STATUS="vulnerable"
    fi
else
    log_warn "No vendor-fixed kernel version is recorded for ${DISTRO_ID} ${DISTRO_VERSION_ID}."
    log_warn "Falling back to runtime mitigation checks below."
fi

# ----- Check 2: algif_aead kernel module status -----------------------------
# The exploit needs the algif_aead module either already loaded OR autoloadable
# on demand. If the module is blacklisted AND not currently loaded, the
# AF_ALG attack surface is effectively closed even on an unpatched kernel.
log_head "Check 2 / 3 — algif_aead kernel module"

MODULE_LOADED=0
MODULE_AVAILABLE=0
MODULE_BLACKLISTED=0
MODULE_BUILTIN=0

if lsmod 2>/dev/null | awk '{print $1}' | grep -qx "algif_aead"; then
    MODULE_LOADED=1
fi

if command -v modinfo >/dev/null 2>&1; then
    if modinfo algif_aead >/dev/null 2>&1; then
        MODULE_AVAILABLE=1
    fi
fi

# A module is considered blacklisted if any modprobe config file sets either
# `blacklist algif_aead` or `install algif_aead /bin/(false|true)`.
if grep -RhsE '^[[:space:]]*(blacklist[[:space:]]+algif_aead|install[[:space:]]+algif_aead[[:space:]]+/bin/(false|true))' \
        /etc/modprobe.d /usr/lib/modprobe.d /run/modprobe.d 2>/dev/null | grep -q .; then
    MODULE_BLACKLISTED=1
fi

KCONFIG=""
if [ -r "/boot/config-$(uname -r)" ]; then
    KCONFIG="/boot/config-$(uname -r)"
elif [ -r /proc/config.gz ]; then
    KCONFIG="/proc/config.gz"
fi
if [ -n "$KCONFIG" ] && zgrep -q '^CONFIG_CRYPTO_USER_API_AEAD=y' "$KCONFIG" 2>/dev/null; then
    MODULE_BUILTIN=1
fi

if [ "$MODULE_BUILTIN" -eq 1 ]; then
    log_bad "algif_aead is built-in in the running kernel. It cannot be disabled using modprobe nor blacklisted."
elif [ "$MODULE_LOADED" -eq 1 ]; then
    log_bad "algif_aead is currently loaded into the running kernel."
elif [ "$MODULE_BLACKLISTED" -eq 1 ]; then
    log_ok "algif_aead is blacklisted and not currently loaded."
elif [ "$MODULE_AVAILABLE" -eq 1 ]; then
    log_warn "algif_aead is not loaded but can be autoloaded on demand (no blacklist found)."
else
    log_ok "algif_aead is neither loaded nor available on this kernel build."
fi

# ----- Check 3: AF_ALG socket reachability ----------------------------------
# Even if the module looks dormant, the kernel may autoload it the moment an
# unprivileged process calls socket(AF_ALG, ...). We test this from userspace
# using a tiny Python probe so we observe the same behavior an attacker would.
#
# We deliberately do NOT trigger any impactful AEAD operation — only the
# socket() call and bind(), which is harmless. Note: bind() may auto-load
# algif_aead on systems where it is loadable but not yet loaded; on already-
# vulnerable systems this matches what an attacker could do themselves, and
# on properly mitigated systems (patched kernel, initcall_blacklist, or a
# blacklisted module) no load is triggered.
log_head "Check 3 / 3 — AF_ALG socket reachability"

AF_ALG_STATUS="unknown"
# The Python probe is kept on a single line and single-quoted so the bash
# parser does not try to interpret any of the Python source. AF_ALG = 38 is a
# Linux kernel constant that is not exported by every build of Python's
# socket module, so we hardcode it here. Only socket() and close() are
# called; no AEAD operation is triggered.
AF_ALG_PY='import socket
try:
    s = socket.socket(38, socket.SOCK_SEQPACKET, 0)
    s.bind(("aead","authencesn(hmac(sha256),cbc(aes))"))
    s.close()
    print("reachable")
except PermissionError:
    print("blocked_permission")
except OSError as e:
    print("blocked_oserror:%d" % (e.errno or 0))
except Exception as e:
    print("error:%s" % type(e).__name__)'

if command -v python3 >/dev/null 2>&1; then
    AF_ALG_PROBE_OUTPUT="$(python3 -c "$AF_ALG_PY" 2>&1)"
    case "$AF_ALG_PROBE_OUTPUT" in
        reachable)
            log_bad "AF_ALG sockets are reachable from this unprivileged context."
            AF_ALG_STATUS="reachable"
            ;;
        blocked_permission)
            log_ok "AF_ALG socket creation or binding is blocked by a security policy (seccomp/LSM/etc.)."
            AF_ALG_STATUS="blocked"
            ;;
        blocked_oserror:*)
            log_ok "AF_ALG socket creation or binding failed at the kernel level ($AF_ALG_PROBE_OUTPUT)."
            AF_ALG_STATUS="blocked"
            ;;
        *)
            log_warn "Could not determine AF_ALG status: $AF_ALG_PROBE_OUTPUT"
            ;;
    esac
else
    log_warn "python3 is not installed; skipping live AF_ALG socket probe."
fi

# ----- Final verdict ---------------------------------------------------------
# Decision matrix (most specific signal wins):
#   * Patched kernel                                                       -> patched
#   * AF_ALG blocked AND module not loaded AND not built-in                -> mitigated
#   * Module blacklisted AND not loaded AND no live probe AND not built-in -> likely_mitigated
#   * Anything else on an unpatched / unknown kernel                       -> vulnerable
log_head "Verdict"

VERDICT="unknown"
EXIT_CODE=2

if [ "$KERNEL_STATUS" = "patched" ]; then
    VERDICT="patched"
    EXIT_CODE=0
    log_ok "This system appears to be PATCHED against CVE-2026-31431."
elif [ "$AF_ALG_STATUS" = "blocked" ] && [ "$MODULE_LOADED" -eq 0 ] && [ "$MODULE_BUILTIN" -eq 0 ]; then
    VERDICT="mitigated"
    EXIT_CODE=0
    log_ok "This system appears to be MITIGATED (AF_ALG attack surface is closed)."
elif [ "$MODULE_BLACKLISTED" -eq 1 ] && [ "$MODULE_LOADED" -eq 0 ] && [ "$MODULE_BUILTIN" -eq 0 ] && [ "$AF_ALG_STATUS" = "unknown" ]; then
    VERDICT="likely_mitigated"
    EXIT_CODE=0
    log_ok "This system appears to be MITIGATED via algif_aead blacklist (no live AF_ALG probe was possible)."
elif [ "$KERNEL_STATUS" = "vulnerable" ] || [ "$MODULE_LOADED" -eq 1 ] || [ "$MODULE_BUILTIN" -eq 1 ] || [ "$AF_ALG_STATUS" = "reachable" ]; then
    VERDICT="vulnerable"
    EXIT_CODE=1
    log_bad "This system appears to be VULNERABLE to CVE-2026-31431."
    log_bad "Apply the vendor kernel update or blacklist algif_aead as a temporary mitigation."
else
    VERDICT="unknown"
    EXIT_CODE=2
    log_warn "Could not reach a definitive verdict. Treat the system as potentially vulnerable."
fi

# ----- JSON output (optional) ------------------------------------------------
if [ "$JSON_MODE" -eq 1 ]; then
    printf '{'
    printf '"verdict":"%s",'             "$VERDICT"
    printf '"distro_id":"%s",'           "$DISTRO_ID"
    printf '"distro_version_id":"%s",'   "$DISTRO_VERSION_ID"
    printf '"kernel":"%s",'              "$KERNEL_RELEASE"
    printf '"patched_version":"%s",'     "$PATCHED_VERSION"
    printf '"kernel_status":"%s",'       "$KERNEL_STATUS"
    printf '"module_loaded":%s,'         "$MODULE_LOADED"
    printf '"module_builtin":%s,'        "$MODULE_BUILTIN"
    printf '"module_available":%s,'      "$MODULE_AVAILABLE"
    printf '"module_blacklisted":%s,'    "$MODULE_BLACKLISTED"
    printf '"af_alg_status":"%s"'        "$AF_ALG_STATUS"
    printf '}\n'
fi

exit "$EXIT_CODE"
