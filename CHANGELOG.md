# Changelog

All notable changes to DeaconGuard are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and DeaconGuard uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). While the major
version is 0, a minor release may include breaking changes; they are listed
under **Changed** with upgrade notes.

## [Unreleased]

## [0.3.1] - 2026-10-08

### Security

- Updated `source-map-js` to 1.2.2 for [GHSA-68fv-2mgg-jv7q](https://github.com/advisories/GHSA-68fv-2mgg-jv7q) (CVE-2026-93749, high severity), an event-loop denial of service through indexed source-map section offsets. It is used only by the web UI's build tools and is not part of the released files, so DeaconGuard installs were not affected.

### Changed

- Updated the SQLite driver (`modernc.org/sqlite`) to 1.60.1.
- Updated the web UI's libraries: `@tanstack/react-query` 5.104.1, `lucide-react` 1.50.0, and `vite` 8.3.2.

## [0.3.0] - 2026-10-08

### Removed

- The last traces of SSH scanning, which DeaconGuard dropped before 0.1.0. Databases from before 0.1.0 lose the hosts registered for SSH scanning and their scan results when they are upgraded; scans still waiting for an SSH answer are marked as interrupted. Hosts on this machine and enrolled agents are not affected. The import of the file-based store (`hosts.json` and `reports/`) used before the database is removed too.
- `host_key_fingerprint` is no longer part of scans in the API.

## [0.2.0] - 2026-10-06

### Added

- **Install script**: `curl -fsSL https://github.com/Cloudopsshell/deaconguard/releases/latest/download/install.sh | sudo sh -s -- --server` (or `--agent`) installs the right `.deb` or `.rpm` for the machine, after checking the package's checksum and, when cosign is installed, the release's signature, and sets it up. Running it again upgrades. `--version` installs a specific release.
- **`deaconguard setup server`** creates the first dashboard account, saves `--listen` and `--tls-cert`/`--tls-key` settings in a systemd drop-in that upgrades keep, starts the server, and prints its addresses and certificate fingerprint. `--admin-user` and `--admin-password-file` set it up without prompts.
- **`deaconguard setup agent`** asks for the enrollment token without showing it, or reads it from `--token-file` or `DEACONGUARD_TOKEN`, enrolls the machine, and starts the agent. An enrolled machine keeps its enrollment unless `--force` is given.
- Signed releases: `checksums.txt.sigstore.json` is a keyless Sigstore signature showing that the release workflow produced `checksums.txt`. See **Verify a release** in the README.

### Changed

- The **Enroll a machine** dialog and `deaconguard token create` show the install command for the server's version, and the token separately to paste when asked, instead of a command line that contains the token.
- `deaconguard user add` and `user passwd` ask for the password on the terminal also when standard input is not one, such as under `curl ... | sudo sh`.

### Removed

- The container image no longer has the `/home/nonroot/.ssh` and `/ssh-keys` directories left over from SSH scanning.

## [0.1.1] - 2026-09-30

### Fixed

- On minimal RHEL-family systems without `shadow-utils`, the `.rpm` installed without creating the `deaconguard` user, so the server service could not start. The packages now depend on `shadow-utils` (`.rpm`) and `passwd` (`.deb`).

### Changed

- The README's Getting started section begins with a table comparing server mode (port 8443) and local mode (port 7480).
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

[Unreleased]: https://github.com/Cloudopsshell/deaconguard/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/Cloudopsshell/deaconguard/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/Cloudopsshell/deaconguard/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Cloudopsshell/deaconguard/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/Cloudopsshell/deaconguard/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Cloudopsshell/deaconguard/releases/tag/v0.1.0
