# Changelog

All notable changes to OpsArmor are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and OpsArmor uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). While the major
version is 0, a minor release may include breaking changes; they are listed
under **Changed** with upgrade notes.

## [Unreleased]

### Added

- **Local scanning**: scan the Linux machine OpsArmor runs on without SSH, with `opsarmor scan --local` for a one-off scan or `opsarmor host add --local` (**Add host → This machine** in the web UI) to register it. Local scans run the same fixed, read-only commands and support every check, including sudo.
- The CI workflow runs a real local scan with every check on an Ubuntu runner.

### Changed

- Scanning no longer depends on SSH internally: the SSH connection is one of several ways to reach a host, preparing for an enrollment-based agent.

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

[Unreleased]: https://github.com/Cloudopsshell/OpsArmor/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/Cloudopsshell/OpsArmor/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Cloudopsshell/OpsArmor/releases/tag/v0.1.0
