# Changelog

All notable changes to DeaconGuard are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and DeaconGuard uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). While the major
version is 0, a minor release may include breaking changes; they are listed
under **Changed** with upgrade notes.

## [Unreleased]

### Fixed

- On minimal RHEL-family systems without `shadow-utils`, the `.rpm` installed without creating the `deaconguard` user, so the server service could not start. The packages now depend on `shadow-utils` (`.rpm`) and `passwd` (`.deb`).

### Changed

- The README's install steps download into `/tmp`, detect the architecture, and stop on a failed download, so the same commands work on every machine and apt shows no "unsandboxed" notice.

## [0.1.0] - 2026-09-30

The first release of DeaconGuard, a Linux security scanner with a server and agents.

### Added

- **Server**: `deaconguard serve --listen 0.0.0.0:8443`, or the `deaconguard-server` service, serves an HTTPS dashboard. It creates a self-signed certificate on first start, or uses yours with `--tls-cert` and `--tls-key`. It requires sign-in with accounts managed by `deaconguard user add|passwd|list|remove`, limits failed sign-ins, and records sign-ins, tokens, enrollments, scans and removals in an **Audit log**.
- **Agents**: `deaconguard agent enroll TOKEN` enrolls a machine with a one-time token from the **Agents** page or `deaconguard token create`. Tokens are valid for 24 hours and can be revoked. The `deaconguard-agent` service then connects out to the server over HTTPS, pinning the certificate fingerprint carried in the token, and runs the scans the server asks for. Agent machines need no open ports and no internet access, because the server evaluates their packages itself. Removing an agent's host revokes it.
- **Local mode**: `deaconguard serve` on localhost gives a dashboard for one machine without accounts, and `deaconguard scan --local` scans the machine it runs on from the terminal.
- **Package vulnerabilities** in installed packages and the running kernel, from official advisories:
  - Ubuntu 18.04 to 26.04 LTS: Canonical CVE OVAL;
  - Debian 12 and 13: Debian Security Tracker;
  - RHEL 8 and 9: Red Hat OVAL;
  - Amazon Linux 2023: ALAS.

  Rules that cannot be evaluated are listed, not reported as clean, and advisory feeds are cached with stale-feed warnings.
- **Optional checks**:
  - **System file integrity** with `dpkg --verify` or `rpm -Va`;
  - **Malware and compromise indicators**;
  - **Security configuration**: SSH, exposed services, pending reboots, automatic updates and firewall;
  - **ClamAV**, run only when it is already installed and memory allows.

  Every command is a fixed, read-only string. Sudo is opt-in per host, and a sudo password is asked for once per scan and kept only in memory. Agents run as root and need no sudo.
- **Dashboard**:
  - severity overview and per-check results for every host;
  - full scan reports with search and filters, and a cross-host CVE view;
  - a live scan console showing each step and command;
  - scan history of the 10 most recent scans per host, with saved logs that can be replayed, and manual deletion.
- **CLI**: `host`, `scan`, `report`, `serve`, `user`, `token`, `agent`, and `version`, sharing one SQLite database with the dashboard.
- **Distribution**: Linux and macOS archives for amd64 and arm64, plus `.deb` and `.rpm` packages. The packages include the systemd units `deaconguard-server.service` and `deaconguard-agent.service`, which are not enabled on install, and a `deaconguard` system user for the server.

[Unreleased]: https://github.com/Cloudopsshell/deaconguard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Cloudopsshell/deaconguard/releases/tag/v0.1.0
