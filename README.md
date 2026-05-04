# Copy Fail Checker — CVE-2026-31431

A small, dependency-light Bash script that tells you whether your Linux system is exposed to the **Copy Fail** local privilege-escalation vulnerability (`CVE-2026-31431`).

The script is **read-only**: it never exploits the bug, never loads kernel modules, and never modifies the system.

---

## What is Copy Fail?

Copy Fail is a logic bug in the Linux kernel's `authencesn` AEAD cryptographic template, reachable from userspace through the `AF_ALG` (`algif_aead`) socket interface.

| Field | Value |
|---|---|
| CVE | `CVE-2026-31431` |
| Disclosed | 2026-04-29 |
| CVSS v3.1 | 7.8 (High) |
| Class | Local Privilege Escalation |
| Affected component | `crypto/authencesn` + `crypto/algif_aead` |
| Introduced in | 2017 (in-place AEAD optimization in `algif_aead.c`) |
| Mainline fix | commit `a664bf3d603d`, merged 2026-04-01 |

### Why it matters

An unprivileged local user can trigger a deterministic, controlled **4-byte write into the page cache** of any file they can read. A public proof-of-concept (732 bytes of Python) uses this primitive to overwrite a setuid binary and obtain root on essentially every mainstream distribution shipped since 2017.

### Who is affected

Every Linux distribution that ships a kernel built since 2017 with `algif_aead` enabled. Confirmed-affected families include:

- Ubuntu 18.04 → 25.10 (Ubuntu 26.04 "Resolute" is not affected)
- Debian (all currently supported suites)
- RHEL / AlmaLinux / Rocky / CentOS Stream 8, 9, 10
- SUSE Linux Enterprise / openSUSE
- Amazon Linux 2023
- Most container hosts and managed-Kubernetes node images derived from the above

---

## Quick start

```bash
# Download the script
curl -fsSLO https://raw.githubusercontent.com/<your-user>/copy-fail-checker/main/check-copy-fail.sh

# Make it executable
chmod +x check-copy-fail.sh

# Run it
./check-copy-fail.sh
```

Or clone the repo:

```bash
git clone https://github.com/<your-user>/copy-fail-checker.git
cd copy-fail-checker
./check-copy-fail.sh
```

The script does not require `root`. Running it as your normal user gives the most realistic view of the attack surface, because that is exactly the context an attacker would have.

---

## What the script checks

The script runs three independent checks and combines them into a single verdict.

### 1. Kernel version

It reads `/etc/os-release` and `uname -r`, then compares your running kernel against the official fixed version published by your distribution's security team. The version table currently covers:

| Distribution | Patched kernel (≥) |
|---|---|
| AlmaLinux / RHEL / Rocky / CentOS 8 | `4.18.0-553.121.1.el8_10` |
| AlmaLinux / RHEL / Rocky / CentOS 9 | `5.14.0-611.49.2.el9_7` |
| AlmaLinux / RHEL / Rocky / CentOS 10 | `6.12.0-124.52.2.el10_1` |
| Ubuntu 26.04+ ("Resolute") | not affected |
| Ubuntu 18.04 – 25.10 | rolling, see `apt` |
| Debian (all suites) | rolling, see DSA |

If your distribution is not in the table, the script falls back to the runtime checks below.

### 2. `algif_aead` module status

The script inspects three things without modifying anything:

- Whether the module is **currently loaded** (`lsmod`)
- Whether the module is **available to load** (`modinfo`)
- Whether the module is **blacklisted** in `/etc/modprobe.d`, `/usr/lib/modprobe.d`, or `/run/modprobe.d`

A blacklisted-and-unloaded module closes the attack surface even on an unpatched kernel.

### 3. `AF_ALG` socket reachability

The most reliable signal is what an attacker would actually see. The script uses a tiny Python probe (`socket.socket(AF_ALG, SOCK_SEQPACKET, 0)`) to find out whether `AF_ALG` sockets can be created at all from an unprivileged context. The probe creates and immediately closes the socket — no crypto state, no AEAD operation, nothing exploitable.

If `python3` is not installed the probe is skipped and the verdict relies on checks 1 and 2.

---

## Possible verdicts

| Verdict | Exit code | Meaning |
|---|---|---|
| `patched` | `0` | Running kernel is at or above the vendor-fixed version. |
| `mitigated` | `0` | `AF_ALG` is blocked and the module is not loaded. |
| `likely_mitigated` | `0` | Module is blacklisted and not loaded; no live probe was possible. |
| `vulnerable` | `1` | Kernel is unpatched and `algif_aead` / `AF_ALG` is reachable. |
| `unknown` | `2` | Not enough signal to decide. Treat as potentially vulnerable. |
| `not_applicable` | `3` | Not running on Linux. |

---

## JSON output for automation

For pipelines, configuration management, or fleet scanning, pass `--json`:

```bash
./check-copy-fail.sh --json
```

Example output:

```json
{
  "verdict": "vulnerable",
  "distro_id": "ubuntu",
  "distro_version_id": "24.04",
  "kernel": "6.8.0-31-generic",
  "patched_version": "",
  "kernel_status": "unknown",
  "module_loaded": 0,
  "module_available": 1,
  "module_blacklisted": 0,
  "af_alg_status": "reachable"
}
```

---

## Mitigation

### Recommended: install the vendor kernel update

This is the only complete fix. After updating, **reboot** so the new kernel is actually running.

```bash
# Debian / Ubuntu
sudo apt update && sudo apt full-upgrade && sudo reboot

# RHEL / AlmaLinux / Rocky / CentOS Stream
sudo dnf clean metadata && sudo dnf upgrade && sudo reboot

# openSUSE / SLES
sudo zypper refresh && sudo zypper update && sudo reboot

# Amazon Linux 2023
sudo dnf upgrade --releasever=latest && sudo reboot
```

### Temporary workaround: disable `algif_aead`

If you cannot reboot into a patched kernel right now, blacklist the vulnerable module. This breaks any application that legitimately uses `AF_ALG` AEAD ciphers (rare on most servers — verify in a staging environment first).

```bash
# Persist the blacklist across reboots
echo "install algif_aead /bin/false" | sudo tee /etc/modprobe.d/disable-algif-aead.conf

# Unload it from the running kernel right now
sudo rmmod algif_aead 2>/dev/null || true
```

For containerized workloads, also block the `AF_ALG` socket family from your seccomp profile so a compromised container cannot reach the kernel surface.

---

## Sample run

```text
== System information ==
[INFO]    Distribution : Ubuntu 24.04.2 LTS (ubuntu 24.04)
[INFO]    Kernel       : 6.8.0-31-generic

== Check 1 / 3 — Kernel version ==
[WARN]    No vendor-fixed kernel version is recorded for ubuntu 24.04.
[WARN]    Falling back to runtime mitigation checks below.

== Check 2 / 3 — algif_aead kernel module ==
[WARN]    algif_aead is not loaded but can be autoloaded on demand (no blacklist found).

== Check 3 / 3 — AF_ALG socket reachability ==
[VULN]    AF_ALG sockets are reachable from this unprivileged context.

== Verdict ==
[VULN]    This system appears to be VULNERABLE to CVE-2026-31431.
[VULN]    Apply the vendor kernel update or blacklist algif_aead as a temporary mitigation.
```

---

## Limitations

- The patched-version table only covers the families listed above. PRs to extend it are welcome.
- The script trusts `uname -r`. If you are running an out-of-tree or rebuilt kernel, the version comparison may not reflect whether the fix was actually backported.
- Live container / sandbox environments may report `blocked_permission` for `AF_ALG` simply because seccomp is in effect — the host kernel itself may still be vulnerable.

---

## References

- [CERT-EU advisory 2026-005](https://cert.europa.eu/publications/security-advisories/2026-005/)
- [Xint disclosure: 732 bytes to root on every major Linux distribution](https://xint.io/blog/copy-fail-linux-distributions)
- [AlmaLinux: CVE-2026-31431 patches released](https://almalinux.org/blog/2026-05-01-cve-2026-31431-copy-fail/)
- [Ubuntu: Copy Fail vulnerability fixes available](https://ubuntu.com/blog/copy-fail-vulnerability-fixes-available)
- [Microsoft Security Blog: Copy Fail in cloud environments](https://www.microsoft.com/en-us/security/blog/2026/05/01/cve-2026-31431-copy-fail-vulnerability-enables-linux-root-privilege-escalation/)
- [Sophos: PoC exploit available](https://www.sophos.com/en-us/blog/proof-of-concept-exploit-available-for-linux-copy-fail-cve-2026-31431)
- [SUSE response to copy.fail](https://www.suse.com/c/suse-responds-to-the-copy-fail-vulnerability/)
- [The Hacker News coverage](https://thehackernews.com/2026/04/new-linux-copy-fail-vulnerability.html)
- [Bugcrowd: What we know about Copy Fail](https://www.bugcrowd.com/blog/what-we-know-about-copy-fail-cve-2026-31431/)
- [The Register coverage](https://www.theregister.com/2026/04/30/linux_cryptographic_code_flaw/)

---

## License

MIT — use, modify, and ship freely. No warranty.
