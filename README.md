# OpsArmor

[![Release](https://img.shields.io/github/v/release/Cloudopsshell/OpsArmor)](https://github.com/Cloudopsshell/OpsArmor/releases/latest)
[![CI](https://github.com/Cloudopsshell/OpsArmor/actions/workflows/ci.yml/badge.svg)](https://github.com/Cloudopsshell/OpsArmor/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/github/license/Cloudopsshell/OpsArmor)](LICENSE)

OpsArmor is a Linux security scanner written in Go. Install it on a Linux machine and it scans that machine: it runs fixed, read-only commands locally and, by default without `sudo`, evaluates the installed packages against the distribution's own security data. Optional checks add system file integrity, malware and compromise indicators, security configuration, and ClamAV antivirus. The matching, checks, and scan orchestration are OpsArmor code; OpsArmor never installs software, and the only third-party engine it runs is a ClamAV that is already installed, when you choose the antivirus check.

> **SSH scanning was removed in 0.2.0.** OpsArmor no longer connects to other machines. To scan a server, install OpsArmor on it. An agent that enrolls with the OpsArmor server using a one-time token, so one dashboard covers many servers, is planned. Hosts registered for SSH scanning by earlier versions keep their results but can no longer be scanned; see [Update](#update).

- [Install](#install) · [Getting started](#getting-started) · [Update](#update) · [Back up and restore](#back-up-and-restore) · [Uninstall](#uninstall)
- [Checks](#checks) · [Web UI](#web-ui) · [Supported distributions](#supported-distributions) · [Versioning](#versioning) · [Development](#development) · [Security](#security)

## Requirements

- **Where OpsArmor runs:** the Linux machine you want to scan, amd64 or arm64, running a [supported distribution](#supported-distributions). It is a single self-contained binary; nothing else is needed. macOS builds are published for viewing results from earlier versions; they cannot scan.
- **Account:** a normal user account is enough; the optional checks see more when [sudo is allowed](#checks).
- **Network:** HTTPS access to the distribution's advisory feed.

## Install

Releases are published on the [Releases page](https://github.com/Cloudopsshell/OpsArmor/releases). Each release has Linux and macOS archives, `.deb` and `.rpm` packages, and a `checksums.txt` file. Replace `0.2.0` below with the version you want.

Downloads need no GitHub account. With the [GitHub CLI](https://cli.github.com) you can also use `gh release download v0.2.0 -R Cloudopsshell/OpsArmor -p 'FILE'`.

### Debian and Ubuntu

```sh
curl -LO https://github.com/Cloudopsshell/OpsArmor/releases/download/v0.2.0/opsarmor_0.2.0_linux_amd64.deb
curl -LO https://github.com/Cloudopsshell/OpsArmor/releases/download/v0.2.0/checksums.txt
sha256sum --check --ignore-missing checksums.txt
sudo apt install ./opsarmor_0.2.0_linux_amd64.deb
opsarmor version
```

### RHEL, Fedora, and Amazon Linux

```sh
curl -LO https://github.com/Cloudopsshell/OpsArmor/releases/download/v0.2.0/opsarmor_0.2.0_linux_amd64.rpm
curl -LO https://github.com/Cloudopsshell/OpsArmor/releases/download/v0.2.0/checksums.txt
sha256sum --check --ignore-missing checksums.txt
sudo dnf install ./opsarmor_0.2.0_linux_amd64.rpm
opsarmor version
```

Use `arm64` instead of `amd64` on ARM machines such as AWS Graviton.

### Other Linux systems and macOS

```sh
curl -LO https://github.com/Cloudopsshell/OpsArmor/releases/download/v0.2.0/opsarmor_0.2.0_linux_amd64.tar.gz
curl -LO https://github.com/Cloudopsshell/OpsArmor/releases/download/v0.2.0/checksums.txt
sha256sum --check --ignore-missing checksums.txt
tar -xzf opsarmor_0.2.0_linux_amd64.tar.gz opsarmor
sudo install -m 0755 opsarmor /usr/local/bin/opsarmor
opsarmor version
```

Pick the archive for your system: `linux_amd64`, `linux_arm64`, `darwin_arm64` (Apple silicon), or `darwin_amd64` (Intel Mac); on macOS, check with `shasum -a 256` instead of `sha256sum`. macOS builds can open results from earlier versions but cannot scan. They are not yet signed by Apple; if macOS blocks the first run of a browser download, allow it with `xattr -d com.apple.quarantine /usr/local/bin/opsarmor`.

### From source

Requires Go 1.26 or later and, for the web UI, Node.js 24 with npm.

```sh
git clone https://github.com/Cloudopsshell/OpsArmor.git && cd OpsArmor
make build          # builds the web UI and the opsarmor binary
./opsarmor version
```

## Getting started

On the Linux machine you want to scan, register it once and open the dashboard:

```sh
opsarmor host add                               # add --allow-sudo to let the deeper checks use sudo
opsarmor serve                                  # then open http://127.0.0.1:7480
```

or work in the terminal:

```sh
opsarmor host list
opsarmor scan HOST_ID --checks packages,malware,config
opsarmor report REPORT_ID --json
```

For a one-off scan without registering the machine:

```sh
opsarmor scan --local --checks packages,integrity,malware,config --allow-sudo
```

The dashboard is served on the machine's loopback address only. To use it from your own computer, forward the port over your usual remote-access tool, for example `ssh -L 7480:127.0.0.1:7480 you@server`, and open <http://127.0.0.1:7480> locally.

## Update

Check your version with `opsarmor version` and read [CHANGELOG.md](CHANGELOG.md) for what changed; any upgrade steps are listed there. [Back up](#back-up-and-restore) your data before updating across a minor version.

| Installed with | Update |
| --- | --- |
| `.deb` | Download the new `.deb` and `sudo apt install ./opsarmor_NEW_linux_ARCH.deb` |
| `.rpm` | Download the new `.rpm` and `sudo dnf install ./opsarmor_NEW_linux_ARCH.rpm` |
| Archive | Download the new archive and replace `/usr/local/bin/opsarmor` with the binary inside |

Stop `opsarmor serve` before replacing the binary and start it again afterwards. The new version upgrades the database automatically on its first start; scans that were running when it stopped are marked as interrupted. Downgrading is not supported once a newer version has upgraded the database: restore the backup taken before the update instead.

**Upgrading to 0.2.0:** SSH scanning is removed. Hosts you registered for SSH scanning stay in the list with their full scan history, marked as no longer scannable; remove them when you no longer need their results. To keep scanning such a server, install OpsArmor on it and run `opsarmor host add` there. The `known_hosts` file in the data directory is no longer used and can be deleted. The container image and Helm chart are no longer published, as they only ran SSH scans.

## Back up and restore

All data lives in one directory: `~/.local/share/opsarmor/` by default, or the path in `OPSARMOR_HOME`. It holds `opsarmor.db` (hosts, scan results, and activity logs) and `feeds/` (a cache that is downloaded again if missing). Files are readable only by their owner, and no passwords are stored there.

To back up, stop `opsarmor serve` and copy the directory:

```sh
cp -a ~/.local/share/opsarmor ~/opsarmor-backup-$(date +%Y%m%d)
```

To restore, stop OpsArmor and copy the backup back into place.

## Uninstall

```sh
sudo apt remove opsarmor                 # Debian and Ubuntu
sudo dnf remove opsarmor                 # RHEL, Fedora, Amazon Linux
sudo rm /usr/local/bin/opsarmor          # archive install
```

Uninstalling keeps your data. To delete it as well, remove `~/.local/share/opsarmor/` (or your `OPSARMOR_HOME`).

## Checks

Each scan runs the checks you choose, in the web UI's scan dialog or with `opsarmor scan HOST_ID --checks packages,integrity,malware,config,antivirus`. Package vulnerabilities is the default.

| Check | What it does | Commands |
| --- | --- | --- |
| Package vulnerabilities | Compares installed packages and the running kernel with official advisories (see [Supported distributions](#supported-distributions)). | `/etc/os-release`, the DPKG status file or `rpm -qa`, `uname -r` |
| System file integrity | Verifies packaged files against the package manager's checksums. Changed binaries and libraries, a classic rootkit sign, are reported; edited configuration files are counted but not reported. | `dpkg --verify` or `rpm -Va` |
| Malware & compromise indicators | Looks for crypto-miner processes, programs running from `/tmp`, `/dev/shm`, memory, or deleted files, programs disguised as kernel threads, `/etc/ld.so.preload`, hidden executables in temporary directories, and download-and-execute or reverse-shell patterns in cron and systemd. This is not a complete antivirus scan. | `/proc`, `ps`, `find` on temporary directories, cron and systemd files |
| Security configuration | Reports SSH root or password login, empty passwords, X11 forwarding, risky services such as Redis, databases, Telnet, or the Docker API listening on all interfaces, pending reboots, disabled automatic updates, and, with sudo, a missing host firewall. | sshd configuration, `ss`/`netstat`, reboot and update settings, firewall rules |
| Antivirus (ClamAV) | Runs the host's own `clamscan` at low priority on temporary, home, and application directories and reports detections and signatures older than 7 days. Skipped when ClamAV is not installed, or when the host has less than about 1.5 GB of free memory and swap, since ClamAV loads its whole signature database into memory. | `clamscan` |

Every command is a fixed string in OpsArmor's source; nothing from the user or the host is inserted into it.

By default checks run as the user running OpsArmor, which cannot see other users' processes, protected files, or firewall rules; results then say they have partial coverage. Allow sudo (`--allow-sudo` when adding the machine or scanning it once, `opsarmor host sudo HOST_ID on`, or the switch on the host page) to run the same read-only commands through `sudo`. If sudo needs a password, the UI or terminal asks for it once per scan and keeps it in memory only; declining continues the scan without sudo. A skipped or failed check is never shown as clean.

## Web UI

`opsarmor serve` starts a local dashboard at <http://127.0.0.1:7480> (change the port with `--listen 127.0.0.1:PORT`). It shows the machine's results, a severity overview, per-check results, full scan reports with search and filters, and scan history. The machine can be added, removed, and scanned from the browser; the CLI and the UI share the same data.

The server only listens on a loopback address and rejects requests addressed to other host names or sent from other websites. While a scan runs, the host's page shows a live console with each step, every fixed command OpsArmor runs (marked when it goes through sudo), how long each took, and findings as each check completes; it never shows command output or credentials. Each scan's activity log is saved with its results, so **View logs** in the scan history replays it later. Scan history keeps the 10 most recent scans per host, plus any older scan that still holds a check's latest result, and each scan can be deleted.

When sudo needs a password, the scan pauses and the browser asks for it. The answer goes to that one scan, is kept in memory only, and is never saved or logged. A wrong password can be retried up to three times; closing the dialog continues the scan without sudo, and an unanswered question stops the scan after 10 minutes.

## Supported distributions

- Ubuntu 18.04, 20.04, 22.04, 24.04, and 26.04 LTS: Canonical CVE OVAL package and running-kernel checks. Unsupported OVAL checks are listed, not treated as clean.
- Debian 12 (Bookworm) and 13 (Trixie): Debian Security Tracker package-source statuses and fixed versions.
- Amazon Linux 2023: ALAS RSS/bulletins and replacement RPM versions. Repository snapshots are immutable; AWS notes that bulletin pages and repository metadata can be temporarily inconsistent.
- Red Hat Enterprise Linux 8 and 9: Red Hat's official OVAL feeds. Unsupported OVAL checks are listed.

CentOS Stream 9/10 is recognized but deliberately rejected: the official repositories checked here publish no `updateinfo` metadata, and RHEL OVAL is not assumed to be compatible. RHEL 10 is not enabled because no official RHEL 10 feed was present in the verified Red Hat feed index. Amazon Linux 2, other RPM distributions, and end-of-life releases are not supported.

Package reports cover the installed DPKG/RPM packages and the running kernel where the platform's feed supports it; they do not cover applications outside the system package manager or containers. The optional checks look for common signs of tampering and misconfiguration, not every possible compromise. No report is a claim that a machine is secure. Missing, invalid, stale-without-cache, or unsupported advisory data must not be interpreted as zero vulnerabilities.

## Versioning

OpsArmor follows [Semantic Versioning](https://semver.org): `MAJOR.MINOR.PATCH`. Patch releases only fix bugs; minor releases add features. Before 1.0.0, a minor release may also contain breaking changes, always listed with upgrade steps in [CHANGELOG.md](CHANGELOG.md). Versions with a suffix, such as `0.2.0-rc.1`, are pre-releases for testing and are marked as such on GitHub. Every binary reports its version with `opsarmor version`, and each scan report records the version that produced it.

## Development

```sh
make build        # web UI and binary, version taken from the nearest git tag
make test vet     # Go tests and vet
make ui-dev       # web UI with hot reload on http://localhost:5173; run ./opsarmor serve alongside it
```

A plain `go build ./cmd/opsarmor` works without Node.js; the binary then explains that the web UI was not built. The UI source is in [web/](web/) and uses React, TypeScript, Vite, Tailwind CSS, TanStack Query, and React Router. Contributions are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md) for the pull request process. Maintainers publish releases as described in [RELEASING.md](RELEASING.md).

## Security

Please report vulnerabilities in OpsArmor privately, as described in [SECURITY.md](SECURITY.md), not in public issues.

## License

OpsArmor is available under the MIT license. Advisory data remains the property and responsibility of its publishing distribution. Only scan systems you own or are authorized to scan.
