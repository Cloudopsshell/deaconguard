# Changelog

All notable changes to DeaconGuard, called OpsArmor before 0.3.0, are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and DeaconGuard uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). While the major
version is 0, a minor release may include breaking changes; they are listed
under **Changed** with upgrade notes.

## [Unreleased]

OpsArmor is now **DeaconGuard**, and becomes a server with agents: one dashboard now scans many machines, without SSH.

### Changed

- **Renamed from OpsArmor to DeaconGuard** (breaking for scripts): the command is `deaconguard`, the package `deaconguard` (it replaces `opsarmor`), the data directory `~/.local/share/deaconguard/`, the database `deaconguard.db`, and the variable `DEACONGUARD_HOME`. Data under the old names is moved on first start, and `OPSARMOR_HOME` is still honored. The repository moved to https://github.com/Cloudopsshell/DeaconGuard; old links redirect.
- Checks run directly, without sudo, when DeaconGuard runs as root.
- Removing an agent host revokes its agent.
- **Upgrade notes:** the database is upgraded to a new schema on first start. `deaconguard serve` on localhost works as before, without sign-in. The CI workflow no longer runs a full local scan.

### Added

- **Server mode**: `deaconguard serve --listen 0.0.0.0:8443` (the new `deaconguard-server` service) serves the dashboard over HTTPS with a self-signed certificate created on first start, or your own with `--tls-cert`/`--tls-key`. It requires sign-in with accounts managed by `deaconguard user add|passwd|list|remove`, limits failed sign-ins, and records sign-ins, tokens, enrollments, scans and removals in an **Audit log** page.
- **Agents**: `deaconguard agent enroll TOKEN` enrolls a machine with a one-time token, created on the new **Agents** page or with `deaconguard token create`. Tokens are valid for 24 hours and can be revoked. The `deaconguard-agent` service then connects out to the server over HTTPS and runs the scans it asks for; the machine needs no open ports and no internet access. Tokens carry the server certificate's fingerprint, which agents pin.
- Agent hosts are scanned from the dashboard or with `deaconguard scan HOST_ID` on the server. Scans wait for an offline agent for up to an hour, and a waiting scan can be cancelled. The server evaluates agents' packages against the advisories itself.
- systemd units `deaconguard-server.service` and `deaconguard-agent.service`, and an `deaconguard` system user, in the `.deb` and `.rpm` packages. Neither service is enabled on install.

## [0.2.0] - 2026-09-29

This release removes SSH scanning: OpsArmor now scans the Linux machine it is installed on. An agent that enrolls with a one-time token, so one OpsArmor server covers many machines, is planned to follow.

### Removed

- **SSH scanning** (breaking): adding and scanning hosts over SSH, SSH host-key trust, key passphrase and SSH password prompts, and the `golang.org/x/crypto` dependency. `opsarmor host add ADDRESS --username ...` now fails with an explanation.
- The container image and the Helm chart, which only ran SSH scans, are no longer published.

### Added

- **Local scanning** of the machine OpsArmor runs on: `opsarmor host add [--allow-sudo]` (**Add this machine** in the web UI) registers it, and `opsarmor scan --local [--allow-sudo]` scans it once without registering it. All checks are supported, including sudo, and the sudo password prompt remains.
- The CI workflow runs a real local scan with every check on an Ubuntu runner.

### Changed

- **Upgrade notes:** hosts registered for SSH scanning stay listed with their full scan history, marked as no longer scannable; remove them when you no longer need their results. To keep scanning such a server, install OpsArmor on it and run `opsarmor host add` there. The `known_hosts` file in the data directory is no longer used and can be deleted.
- Scanning runs through a transport-neutral interface, ready for the planned agent.

## [0.1.1] - 2026-09-29

### Security

- Updated `golang.org/x/crypto` to v0.57.0 and `golang.org/x/net` to v0.59.0. OpsArmor 0.1.0 reached 17 known vulnerabilities in them: a malicious or faulty SSH server, such as a compromised scanned host, could crash or hang a scan, `@revoked` entries in `known_hosts` files were not enforced, and malformed Amazon Linux bulletin pages could crash or slow the scanner. All users should upgrade.

### Added

- `SECURITY.md` with how to report vulnerabilities privately, and `CONTRIBUTING.md` with the pull request process.

## [0.1.0] - 2026-09-29

The first release of OpsArmor.

### Added

- **Package vulnerability scanning** over SSH, without an agent or root access, against each distribution's official advisories: Ubuntu 18.04–26.04 LTS (Canonical OVAL), Debian 12 and 13 (Debian Security Tracker), Red Hat Enterprise Linux 8 and 9 (Red Hat OVAL), and Amazon Linux 2023 (ALAS). Rules that cannot be evaluated are reported, never counted as clean.
- **Optional checks** chosen per scan:
  - *System file integrity* with `dpkg --verify` or `rpm -Va`, reporting changed binaries and libraries.
  - *Malware and compromise indicators*: crypto miners, programs running from temporary directories, memory, or deleted files, fake kernel threads, `/etc/ld.so.preload`, and suspicious cron and systemd entries.
  - *Security configuration*: SSH root and password login, risky services listening on all interfaces, pending reboots, automatic updates, and the host firewall.
  - *Antivirus* with the host's own ClamAV when it is installed, skipped when the host lacks the memory to run it safely.
- **Per-host sudo consent** for deeper checks, using passwordless sudo or a password asked for once per scan.
- **Local web UI** (`opsarmor serve`, loopback only): dashboard, hosts, per-check result tabs, scan reports with search and filters, cross-host CVE view, and scan history.
- **Live scan console** showing each step, the fixed commands run on the host, and findings as they arrive; each scan's log is saved and can be replayed with **View logs**.
- **Interactive prompts** in the browser and the terminal for new SSH host keys, key passphrases, SSH passwords, and sudo passwords. Answers are held in memory for one scan and never stored.
- **SQLite storage** shared by the CLI and the web UI, with automatic schema upgrades and a one-time import of the earlier JSON profiles and reports.
- **Scan history** limited to the 10 most recent scans per host, keeping any older scan that still holds a check's latest result, with manual deletion.
- `opsarmor version`, and the version in the web UI, in every report, and in requests to advisory feeds.
- **Distribution**: Linux and macOS archives for amd64 and arm64, `.deb` and `.rpm` packages, a multi-architecture container image on GHCR, and a Helm chart for scheduled scans.

[Unreleased]: https://github.com/Cloudopsshell/DeaconGuard/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Cloudopsshell/DeaconGuard/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/Cloudopsshell/DeaconGuard/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Cloudopsshell/DeaconGuard/releases/tag/v0.1.0
