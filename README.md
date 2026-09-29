# OpsArmor

[![Release](https://img.shields.io/github/v/release/Cloudopsshell/OpsArmor)](https://github.com/Cloudopsshell/OpsArmor/releases/latest)
[![CI](https://github.com/Cloudopsshell/OpsArmor/actions/workflows/ci.yml/badge.svg)](https://github.com/Cloudopsshell/OpsArmor/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/github/license/Cloudopsshell/OpsArmor)](LICENSE)

OpsArmor is an agentless Linux security scanner written in Go. It connects only to hosts you register, runs fixed read-only commands over SSH, and by default evaluates the installed packages against the distribution's own security data without `sudo`. Optional checks add system file integrity, malware and compromise indicators, security configuration, and ClamAV antivirus. The matching, checks, and scan orchestration are OpsArmor code; OpsArmor never installs software on a host, and the only third-party engine it runs is a ClamAV that is already installed there, when you choose the antivirus check.

- [Install](#install) · [Getting started](#getting-started) · [Update](#update) · [Back up and restore](#back-up-and-restore) · [Uninstall](#uninstall)
- [Checks](#checks) · [Web UI](#web-ui) · [Supported distributions](#supported-distributions) · [Versioning](#versioning) · [Development](#development) · [Security](#security)

## Requirements

- **Where OpsArmor runs:** Linux or macOS on amd64 or arm64. It is a single self-contained binary; nothing else is needed.
- **Scanned hosts:** reachable over SSH, or the Linux machine OpsArmor runs on, running a [supported distribution](#supported-distributions). A normal account that can read `/etc/os-release` and the package database is enough; the optional checks see more when [sudo is allowed](#checks) for the host.
- **Network:** HTTPS access from the machine running OpsArmor to the distribution's advisory feed.

## Install

Releases are published on the [Releases page](https://github.com/Cloudopsshell/OpsArmor/releases). Each release has Linux and macOS archives, `.deb` and `.rpm` packages, a `checksums.txt` file, a container image, and a Helm chart. Replace `0.1.0` below with the version you want.

Downloads need no GitHub account. With the [GitHub CLI](https://cli.github.com) you can also use `gh release download v0.1.0 -R Cloudopsshell/OpsArmor -p 'FILE'`.

### Debian and Ubuntu

```sh
curl -LO https://github.com/Cloudopsshell/OpsArmor/releases/download/v0.1.0/opsarmor_0.1.0_linux_amd64.deb
curl -LO https://github.com/Cloudopsshell/OpsArmor/releases/download/v0.1.0/checksums.txt
sha256sum --check --ignore-missing checksums.txt
sudo apt install ./opsarmor_0.1.0_linux_amd64.deb
opsarmor version
```

### RHEL, Fedora, and Amazon Linux

```sh
curl -LO https://github.com/Cloudopsshell/OpsArmor/releases/download/v0.1.0/opsarmor_0.1.0_linux_amd64.rpm
curl -LO https://github.com/Cloudopsshell/OpsArmor/releases/download/v0.1.0/checksums.txt
sha256sum --check --ignore-missing checksums.txt
sudo dnf install ./opsarmor_0.1.0_linux_amd64.rpm
opsarmor version
```

Use `arm64` instead of `amd64` on ARM machines such as AWS Graviton.

### macOS and other Linux systems

```sh
curl -LO https://github.com/Cloudopsshell/OpsArmor/releases/download/v0.1.0/opsarmor_0.1.0_darwin_arm64.tar.gz
curl -LO https://github.com/Cloudopsshell/OpsArmor/releases/download/v0.1.0/checksums.txt
shasum -a 256 --check --ignore-missing checksums.txt
tar -xzf opsarmor_0.1.0_darwin_arm64.tar.gz opsarmor
sudo install -m 0755 opsarmor /usr/local/bin/opsarmor
opsarmor version
```

Pick the archive for your system: `darwin_arm64` (Apple silicon), `darwin_amd64` (Intel Mac), `linux_amd64`, or `linux_arm64`. Release binaries are not yet signed by Apple; if you downloaded the archive in a browser, macOS may block the first run. Allow it with `xattr -d com.apple.quarantine /usr/local/bin/opsarmor`.

### Container

```sh
docker pull ghcr.io/cloudopsshell/opsarmor:v0.1.0
docker volume create opsarmor-data
docker run --rm -it \
	-v opsarmor-data:/data \
	-v "$HOME/.ssh:/ssh-keys:ro" \
	-v "$HOME/.ssh:/home/nonroot/.ssh:ro" \
	ghcr.io/cloudopsshell/opsarmor:v0.1.0 \
	host add ubuntu.example.com --username ubuntu --key-path /ssh-keys/id_ed25519
```

The image keeps host profiles, scan history, feed cache, and host-key pins in the `/data` volume and runs as a non-root user. It is meant for the CLI and scheduled scans: the web UI only listens on the loopback address, so run `opsarmor serve` on your own machine instead. Tags: `v0.1.0` (exact release), `v0.1` (latest patch of that minor version), and `latest` (newest stable release; pre-releases never move it). If the image is not yet public, sign in first with `docker login ghcr.io` using a token that can read packages.

### Kubernetes (Helm)

The Helm chart runs scheduled scans as CronJobs, one per configured host; it is not a dashboard service. Download the chart from the release and install it with your values:

```sh
curl -LO https://github.com/Cloudopsshell/OpsArmor/releases/download/v0.1.0/opsarmor-0.1.0.tgz
helm upgrade --install opsarmor ./opsarmor-0.1.0.tgz -n opsarmor --create-namespace -f my-values.yaml
```

Supply host profiles, a pre-created Secret containing the private key files, and independently verified host keys; private keys are never stored in Helm values or ConfigMaps. See [the chart README](charts/opsarmor/README.md) and [example values](charts/opsarmor/values.example.yaml).

### From source

Requires Go 1.26 or later and, for the web UI, Node.js 24 with npm.

```sh
git clone https://github.com/Cloudopsshell/OpsArmor.git && cd OpsArmor
make build          # builds the web UI and the opsarmor binary
./opsarmor version
```

## Getting started

Register a host you own or are authorized to scan, then scan it from the web UI or the terminal:

```sh
opsarmor host add ubuntu.example.com --username ubuntu --key-path ~/.ssh/id_ed25519
opsarmor serve                                  # then open http://127.0.0.1:7480
```

or, in the terminal:

```sh
opsarmor host list
opsarmor scan HOST_ID --checks packages,malware,config
opsarmor report REPORT_ID --json
```

To scan the Linux machine OpsArmor is installed on, no SSH is needed. Register it once with `opsarmor host add --local` (or **Add host → This machine** in the web UI), or run a one-off scan:

```sh
opsarmor scan --local --checks packages,malware,config
sudo opsarmor scan --local --checks integrity,malware   # or add --allow-sudo to use sudo for the deeper checks
```

Local scans run the same fixed, read-only commands directly as the user running OpsArmor, and are available on Linux only.

The first connection to a host shows its SSH host-key fingerprint and asks you to trust it. Compare it with your cloud console or another trusted source first: this is trust-on-first-use, and once a key is trusted any change to it is refused. Encrypted keys and password logins are asked for when needed, in the browser or the terminal; for unattended use, load keys into `ssh-agent`.

## Update

Check your version with `opsarmor version` and read [CHANGELOG.md](CHANGELOG.md) for what changed; any upgrade steps are listed there. [Back up](#back-up-and-restore) your data before updating across a minor version.

| Installed with | Update |
| --- | --- |
| `.deb` | Download the new `.deb` and `sudo apt install ./opsarmor_NEW_linux_ARCH.deb` |
| `.rpm` | Download the new `.rpm` and `sudo dnf install ./opsarmor_NEW_linux_ARCH.rpm` |
| Archive | Download the new archive and replace `/usr/local/bin/opsarmor` with the binary inside |
| Container | `docker pull ghcr.io/cloudopsshell/opsarmor:vNEW` and use the new tag with the same `/data` volume |
| Helm | `helm upgrade opsarmor ./opsarmor-NEW.tgz -n opsarmor -f my-values.yaml` |

Stop `opsarmor serve` before replacing the binary and start it again afterwards. The new version upgrades the database automatically on its first start; scans that were running when it stopped are marked as interrupted. Downgrading is not supported once a newer version has upgraded the database: restore the backup taken before the update instead.

## Back up and restore

All data lives in one directory: `~/.local/share/opsarmor/` by default, or the path in `OPSARMOR_HOME` (`/data` in the container). It holds `opsarmor.db` (hosts, scan results, and activity logs), `known_hosts` (trusted host keys), and `feeds/` (a cache that is downloaded again if missing). Files are readable only by their owner, and no private keys or passwords are stored there.

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
helm uninstall opsarmor -n opsarmor      # Helm
```

Uninstalling keeps your data. To delete it as well, remove `~/.local/share/opsarmor/` (or your `OPSARMOR_HOME`), or the `opsarmor-data` volume for containers.

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

By default checks run as the SSH user, which cannot see other users' processes, protected files, or firewall rules; results then say they have partial coverage. Allow sudo for a host (`--allow-sudo` when adding it, `opsarmor host sudo HOST_ID on`, or the switch on the host page) to run the same read-only commands through `sudo`. If sudo needs a password, the UI or terminal asks for it once per scan and keeps it in memory only; declining continues the scan without sudo. A skipped or failed check is never shown as clean.

## Web UI

`opsarmor serve` starts a local dashboard at <http://127.0.0.1:7480> (change the port with `--listen 127.0.0.1:PORT`). It shows every registered host, a severity overview, per-check results, full scan reports with search and filters, scan history, and which hosts are affected by each CVE. Hosts can be added, removed, and scanned from the browser; the CLI and the UI share the same data.

The server only listens on a loopback address and rejects requests addressed to other host names or sent from other websites. While a scan runs, the host's page shows a live console with each step, every fixed command OpsArmor runs on the host (marked when it goes through sudo), how long each took, and findings as each check completes; it never shows command output or credentials. Each scan's activity log is saved with its results, so **View logs** in the scan history replays it later. Scan history keeps the 10 most recent scans per host, plus any older scan that still holds a check's latest result, and each scan can be deleted.

When a scan needs something from you, it pauses and the browser asks: to approve a new host's SSH key fingerprint, for the passphrase of an encrypted key that `ssh-agent` does not already hold, for the SSH password when the server rejects the keys and accepts passwords, or for the sudo password. Answers go to that one scan, are kept in memory only, and are never saved or logged. A wrong answer can be retried up to three times; closing the dialog cancels the scan, and an unanswered question stops the scan after 10 minutes.

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

OpsArmor is available under the MIT license. Advisory data remains the property and responsibility of its publishing distribution. Only register systems you own or are authorized to scan.
