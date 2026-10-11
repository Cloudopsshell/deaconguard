# Changelog

All notable changes to DeaconGuard are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and DeaconGuard uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). While the major
version is 0, a minor release may include breaking changes; they are listed
under **Changed** with upgrade notes.

## [Unreleased]

## [0.9.1] - 2026-10-11

### Fixed

- The **This server** label broke across two lines when the host column was narrow. It now stays in one piece and moves to the next line as a whole.
- The **Agents** page now marks the server's own agent with **This server**, and says its token came from server setup rather than "deaconguard (cli)".

## [0.9.0] - 2026-10-11

### Added

- **The server's own machine is scanned as root, by an agent of its own.** The server runs without root, as the `deaconguard` user, and systemd's `NoNewPrivileges` keeps it from using sudo, so scans of its own machine were always partial. `deaconguard setup server`, which the install script runs, now installs and enrolls an agent on the server's machine over `127.0.0.1`. It appears on the Hosts page as **This server**, and its scans have full coverage, scheduled or not. The server still runs without root, and the agent listens on nothing.
- `--no-agent` skips it (and is remembered by later runs); `--with-agent` adds it later.
- Setup ends by saying what runs on the machine, and how.
- A host the server scans itself shows why its results are partial and how to fix it.

### Changed

- **The server never scans anything itself.** In the dashboard on a server, **Add this machine** gives way to **Enroll a machine**; the local dashboard (`deaconguard serve`) keeps it.
- **Upgrading:** running the install script on a server adds the agent. If this machine was added as a host earlier, its scans, log entries, and schedules move to the agent host. The install script now recognizes a server's machine as a server even though it also has an agent.

## [0.8.1] - 2026-10-11

### Fixed

- **Editing a schedule, and turning it off or on, failed** with "invalid request body: json: unknown field "id"". The dashboard sent the whole schedule back, including read-only fields the server rightly refuses; it now sends only the fields you can change.

## [0.8.0] - 2026-10-10

### Added

- **Scheduled scans.** A new **Schedules** page scans hosts automatically, so results no longer go stale when nobody presses Scan now:
  - choose the days (every day, weekdays, or any days of the week), a time and a time zone; daylight saving changes are handled, and a schedule runs once per day even when the clocks go back;
  - choose all hosts (including hosts added later) or specific hosts, and the checks, including the advanced antivirus scan;
  - **Run now**, **Turn off** and **Turn on**, edit and delete.
- The server starts each run's scans like Scan now. It skips a host that is already being scanned, or whose agent is too old for a chosen check, and says why in the Logs page. A run missed while the server was stopped happens once when it starts again.
- **Schedules run with root privileges by default.** Agents run as root; the server's own machine uses sudo where it needs no password, since a scheduled scan never waits for one. A schedule can turn root off, and the dialog then reminds you that results will show partial coverage.
- Each host's page shows its next scheduled scan, or that it is not on a schedule. The dashboard flags hosts whose latest results are more than 7 days old.
- The audit log records creating, changing, running and deleting schedules, and names the schedule that started each scan. It now also names viewing and downloading the log.

### Changed

- **Upgrading:** the database gains a schedules table (schema 9). No schedule exists until you create one.

## [0.7.1] - 2026-10-10

### Fixed

- **Upgrading restarts each service once instead of twice.** The package already restarts a running service with the new version; `deaconguard setup`, which the install script runs next, restarted it again, so the Logs page showed "started, stopped, started" and the agent's start line twice. Setup now restarts a running service only when it changed something the service must pick up: the server's address or certificate, its first account, or a new enrollment. It says so when it leaves the service running.

## [0.7.0] - 2026-10-10

### Added

- **Every package finding says what clears it**, on Ubuntu, Debian, Red Hat and Amazon Linux: **Update available**, **Restart needed** (the fixed kernel is installed but not running), **Old kernel** (installed but not running), **Ubuntu Pro** (fixed only in ESM), or **No fix yet** (the distribution has not published a fix, so updating cannot help).
- **The dashboard leads with what you can fix now.** A host that is fully up to date shows "Nothing to fix now", with the findings that wait on the distribution listed separately, never as clean. The host page has a **What to do** card with each group's packages and the command for that distribution, and its findings open on **Fix now**. The dashboard, host list, scan history and Vulnerabilities page count findings to fix now, and show how many are waiting.
- The CLI's package summary groups findings the same way.

### Changed

- **Ubuntu findings use Ubuntu's own priority as their severity**, instead of the generic CVSS rating first. Ubuntu rates many CVEs lower for how the package is built and used on Ubuntu; for example, CVEs Ubuntu rates low were shown as critical. The CVSS rating is still shown beside the severity when it differs. Debian, Red Hat and Amazon Linux already used their own ratings.
- **Upgrading:** the database gains fix states (schema 8). Findings from earlier scans are marked from whether a fixed version exists, and Ubuntu severities update with the next scan.

## [0.6.0] - 2026-10-10

### Added

- **A Logs page** shows what the server and each agent did, newest first, so you no longer need SSH and `journalctl` to find out what happened:
  - the server: starts and stops, with why the previous run ended; agents connecting and no longer checking in; enrollments; each scan's start (and by whom), finish and failure; and every warning and error a scan reported, such as a stale advisory feed or a check that was skipped;
  - each agent's own log, sent to the server over its existing connection. Lines from while the server was unreachable are kept on the agent (up to 2,000) and arrive once it answers again.

  Filter by server or agents, machine, level and text; follow new entries live; or download the filtered log as text. Each host's page shows its latest entries. Entries are kept for 7 days, at most 100,000.
- Reading the log needs a signed-in account. Downloads are recorded in the audit log, and so is viewing the log, at most once per account every 15 minutes.

### Changed

- **Upgrading:** agents send their log from 0.6.0; run the install script on each agent to upgrade. Older agents keep working, and their host page says their log is in the machine's journal only. The database gains a `logs` table (schema 7); downgrading to 0.5.x keeps working and ignores it.

## [0.5.2] - 2026-10-10

### Fixed

- **Checking an Ubuntu machine's packages needs about 450 MB on the server instead of 1.6 GB**, so the server no longer runs out of memory on small machines mid-scan. The Ubuntu feed is now parsed as it is decompressed, and only the parts the evaluation reads are kept. Results are unchanged: on a real Ubuntu 24.04 package list, all 20,568 findings are identical before and after.
- The server checks one machine's packages at a time instead of two, so its memory stays the same however many agents report together. Each check takes a few seconds.

### Changed

- The server needs at least **1 GB of memory** (RAM plus swap), down from 2 GB.

## [0.5.1] - 2026-10-10

### Fixed

- **A scan cut short by a server restart now says why**, instead of "scan was interrupted before it finished": the machine restarted, it ran out of memory and the kernel stopped the server, DeaconGuard crashed (with the crash report), or it was stopped by a signal. For example: "The DeaconGuard server stopped while this scan was running. The machine ran out of memory and the kernel stopped the DeaconGuard server. Run the scan again."

### Added

- **The dashboard says when the server restarted unexpectedly**, and why, in a notice at the top of every page for 7 days or until dismissed. A crash shows its report. The server also writes the reason to its journal when it starts.
  - The server service gains `ExecStopPost=-/usr/bin/deaconguard record-stop`, which records how systemd saw the server end. Upgrading with the install script or the package installs it.
- The requirements state the server's memory: at least 2 GB, RAM plus swap. Checking an Ubuntu 24.04 machine briefly needs about 1.6 GB on the server.

## [0.5.0] - 2026-10-10

### Added

- **Advanced antivirus scan.** The antivirus scan is now **Basic** (ClamAV, as before, and still the default) or **Advanced**, which also runs [YARA-X](https://virustotal.github.io/yara-x/) with the [YARA Forge](https://github.com/YARAHQ/yara-forge) core rules for webshells, crypto miners, backdoors, and attacker tools that signature scanners often miss. Choose it in the scan dialog, or add `yara` to `--checks`.
  - The server downloads the latest weekly rules from GitHub, keeps them for 12 hours, and sends them to agents with each scan, over the agent connection. On the host they are written to a private temporary file and deleted afterwards.
  - Matches are reported with the rule's name, author, reference, and a severity from the rule's score. A match is a strong lead, not proof: look at the file before acting.
  - Agents need 0.5.0 or later; the server refuses an Advanced scan on an older agent and says to upgrade it. Basic scans work as before.
- **The install script installs YARA-X 1.21.0** (`yr`) to `/usr/local/bin`, a pinned version checked against a pinned checksum, and release notes list it with the other dependencies.

### Changed

- The "Antivirus (ClamAV)" check is now called **Antivirus scan**.
- **Upgrading:** run the install script again on the server and on each agent, as for any upgrade. It installs YARA-X along with the new version. The Advanced scan works on agents once they run 0.5.0; until then the server refuses it on that agent and shows the command to upgrade it.

## [0.4.2] - 2026-10-10

### Changed

- **The install commands say up front that they run as root**, instead of the script asking for a sudo password part-way through:
  - Server: `curl -fsSL https://get.deaconguard.io | sudo sh -`
  - Agent: `curl -fsSL https://get.deaconguard.io | DEACONGUARD_TOKEN=… sudo -E sh -`. `-E` passes the token through the environment, so it never appears in the process list other users can read.

  Started without root, the installer stops before doing anything and shows the command to use; it no longer calls sudo itself. As root, run the commands without `sudo`. The **Enroll a machine** dialog, `deaconguard token create` and the README show the new commands.
- **The install script installs what DeaconGuard's checks use**, on servers and agents, from the distribution's own repositories: `procps`, `iproute2` / `iproute`, `findutils`, `needs-restarting` (RHEL family), and ClamAV with its signature updater, which it switches on. On RHEL it enables EPEL, which provides ClamAV there. On minimal systems the malware, configuration and antivirus checks previously had only partial coverage.
- **Every install verifies the release signature.** The script installs cosign (a pinned version with a pinned checksum) when it is missing, instead of skipping the signature check.

### Added

- Release notes list the Go version and main libraries a release was built with, and what the install script installs on each machine.
- Each release carries an SBOM, `deaconguard_X.Y.Z_sbom.spdx.json`, listing every Go module and web UI package with versions and licenses.

## [0.4.1] - 2026-10-10

### Changed

- The install command is now `curl -fsSL https://get.deaconguard.io | sh -`. The **Enroll a machine** dialog and `deaconguard token create` show the agent command with `get.deaconguard.io`, still pinned to the server's version with `DEACONGUARD_VERSION`. The GitHub release URLs keep working.
- The README links to the new website and documentation at [deaconguard.io](https://deaconguard.io) and [docs.deaconguard.io](https://docs.deaconguard.io).
- `SECURITY.md` describes the supported versions (the latest minor version) and how the server, agents and releases limit risk.

### Fixed

- Messages and help text said "an DeaconGuard"; they now say "a DeaconGuard".
- The README said agents trust only the server's pinned certificate. They also accept a certificate their system's certificate authorities trust for the server's name, which lets a server switch to its own certificate without enrolling agents again.

## [0.4.0] - 2026-10-09

### Changed

- The install script works like k3s's: `curl -fsSL …/install.sh | sh -` installs a server, and `curl -fsSL …/install.sh | DEACONGUARD_TOKEN=… sh -` installs and enrolls an agent. Run it as a normal user; it uses `sudo` for the steps that need root. On a machine that is already an enrolled agent, running it without a token upgrades the agent. `DEACONGUARD_VERSION` picks a release. `--server`, `--agent`, `--version` and pasting the token at a prompt keep working.
- The **Enroll a machine** dialog and `deaconguard token create` show one command that installs and enrolls the agent, with the one-time token in it. The token alone stays available for pasting.

## [0.3.2] - 2026-10-09

### Security

- Built with Go 1.26.9, which fixes 10 vulnerabilities in the Go standard library that the DeaconGuard server's HTTPS listener and the agent's connection to it use, among them an HTTP/2 server crash ([GO-2026-6617](https://pkg.go.dev/vuln/GO-2026-6617)) and HTTP/2 memory exhaustion through trailer headers ([GO-2026-6603](https://pkg.go.dev/vuln/GO-2026-6603)). The other fixes are GO-2026-6605, GO-2026-6607 to GO-2026-6613, in `net/http`, `crypto/tls` and `net/textproto`. Upgrade servers first, then agents.
- Updated `golang.org/x/net` to 0.60.0. DeaconGuard does not call the vulnerable code it fixes.

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

[Unreleased]: https://github.com/Cloudopsshell/deaconguard/compare/v0.9.1...HEAD
[0.9.1]: https://github.com/Cloudopsshell/deaconguard/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/Cloudopsshell/deaconguard/compare/v0.8.1...v0.9.0
[0.8.1]: https://github.com/Cloudopsshell/deaconguard/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/Cloudopsshell/deaconguard/compare/v0.7.1...v0.8.0
[0.7.1]: https://github.com/Cloudopsshell/deaconguard/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/Cloudopsshell/deaconguard/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/Cloudopsshell/deaconguard/compare/v0.5.2...v0.6.0
[0.5.2]: https://github.com/Cloudopsshell/deaconguard/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/Cloudopsshell/deaconguard/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/Cloudopsshell/deaconguard/compare/v0.4.2...v0.5.0
[0.4.2]: https://github.com/Cloudopsshell/deaconguard/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/Cloudopsshell/deaconguard/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/Cloudopsshell/deaconguard/compare/v0.3.2...v0.4.0
[0.3.2]: https://github.com/Cloudopsshell/deaconguard/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/Cloudopsshell/deaconguard/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/Cloudopsshell/deaconguard/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Cloudopsshell/deaconguard/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/Cloudopsshell/deaconguard/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Cloudopsshell/deaconguard/releases/tag/v0.1.0
