# Changelog

All notable changes to DeaconGuard are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and DeaconGuard uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). While the major
version is 0, a minor release may include breaking changes; they are listed
under **Changed** with upgrade notes.

## [Unreleased]

## [0.15.0] - 2026-10-13

### Added

- **Container image.** `ghcr.io/cloudopsshell/deaconguard`, for amd64 and arm64: the same binary on a minimal base image with no shell, running as a non-root user, signed keyless like the release files, with its SBOM attached.
- **Docker Compose.** `deploy/compose/compose.yaml` runs the server with its data in a volume, and, with `--profile agent`, an agent that scans the machine Compose runs on.
- **Kubernetes.** A Helm chart, `oci://ghcr.io/cloudopsshell/charts/deaconguard`, also signed, and Kustomize manifests in `deploy/kustomize`: the server as a StatefulSet with a volume, under the restricted Pod Security Standard, and an agent DaemonSet that scans every node, with an ingress example.
- **The agent scans the host from a container.** With the host's root filesystem mounted read-only and `DEACONGUARD_HOST_ROOT` set to it, the agent runs its checks there with the host's own tools, so the results match an agent installed on the host. `DEACONGUARD_HOSTNAME` sets the name it reports, such as the node's.
- **Reusable enrollment tokens.** **Enroll a machine** offers **Many machines**: a token that enrolls any number of machines for 1 to 365 days, with a name, until revoked. The **Agents** page counts the machines each has enrolled. On the command line: `deaconguard token create --reusable [--days N] [--name NAME] [--quiet]`.
- **Agents enroll themselves** from a token in their environment, `DEACONGUARD_ENROLL_TOKEN_FILE` or `DEACONGUARD_ENROLL_TOKEN`, when not enrolled yet, when the token is for a server with another certificate, or when the server no longer knows them.
- **The first account from the environment:** `deaconguard serve` creates it from `DEACONGUARD_ADMIN_USER` and `DEACONGUARD_ADMIN_PASSWORD_FILE` (or `DEACONGUARD_ADMIN_PASSWORD`) when there is none.
- **Trusted proxies:** `deaconguard serve --trusted-proxy CIDR`, or `DEACONGUARD_TRUSTED_PROXIES`, takes each client's address from `X-Forwarded-For` when the request comes through those proxies, so sign-in limits and the audit log work behind an ingress.

### Changed

- **Upgrading:** the database gains reusable tokens (schema 15). Nothing else changes for package installs.

## [0.14.0] - 2026-10-12

### Added

- **Compliance views.** Every baseline control, and the checks for vulnerabilities, file integrity and malware, are mapped to requirements of **NIST SP 800-53 Rev. 5**, **PCI DSS v4.0**, the **HIPAA Security Rule** and **ISO/IEC 27001:2022 Annex A**. An audit's page has a **Compliance** card with a tab per framework showing each requirement as met, met with an accepted risk, not met or not checked, with the controls behind it. Reports can include the mapping for the frameworks you choose. It's DeaconGuard's mapping, for guidance, not a certification; requirements are referred to by number.
- **Custom policies.** Admins add their own controls in YAML on a new **Policies** page (from **Settings**): SSH and kernel settings, login.defs, packages, services, mounts, listening ports and the permissions of key files. Policies test only what the audit already reads and never run anything. Results show on audits and in reports, failed controls can have accepted risks, and the grade isn't affected. Saving a policy says exactly what's wrong with it.
- **10 more baseline controls, 72 in all:** password history, locking unused accounts, a lockout threshold, the SSH banner and log level, core dumps, USB storage, signed package sources, private home directories and log file permissions.

### Changed

- The hardening check sends the settings it read with its results, so the server can test policies. It now reads every kernel setting.
- **Upgrading:** the database gains policies (schema 14). Upgrade agents to 0.14.0 for the new controls and for policies: an older agent's audit has the 62 controls it knows, and its policy controls show as not checked.

## [0.13.0] - 2026-10-12

### Added

- **Reports.** **Create report** on an audit's or a scan's page freezes it as a report for a client, with an optional client name and notes, and, for audits, a comparison with an earlier audit of the host: the controls fixed since then, those that started failing, and the earlier grade.
- **Downloads in five formats**, all rendered from the same frozen report:
  - **PDF**: a cover page with your logo, company, contact line, the client, the grade and score; a summary; changes since the earlier audit; failed controls with evidence, why they matter and how to fix them; accepted risks; passed controls; vulnerabilities (fixable ones listed, the rest grouped by package); other findings; the inventory. Made by the server, with nothing to install.
  - **HTML**, one page that prints well; **Excel**, with Summary, Items (filterable) and Inventory sheets; **CSV**; **JSON**.
- **Branding:** a new admin **Settings** page sets the company name, contact line and logo (PNG or JPEG, up to 256 KB) for every new report.
- **Share links:** a link that opens a report without signing in, with its downloads, for 1 to 30 days until revoked. Only a hash of it is stored; views are counted and recorded in the audit log.
- **Verify a report:** every report shows its ID and a SHA-256 fingerprint; the new page checks them against what the server made.
- Creating, downloading, sharing and deleting reports, and changing the branding, are recorded in the audit log.

### Changed

- Spreadsheet cells that would start a formula are prefixed, since evidence comes from the scanned machine.
- **Upgrading:** the database gains reports and share links (schema 13).

## [0.12.0] - 2026-10-12

### Added

- **Server audits.** **Run audit** on a host's page checks the machine from top to bottom and grades it A to F, for handing a newly built server over or checking an existing one. An audit runs every check, plus an antivirus scan (optionally the advanced one), and records the machine's inventory: OS, kernel, hardware, memory, uptime, disks, addresses, listening services, administrators, accounts that can log in, time zone and clock synchronisation.
- **The hardening audit check** (`hardening`): the 62 controls of the new DeaconGuard Linux baseline, in 10 categories: accounts and passwords, SSH, network, kernel, services and the firewall, logging and auditing, files and permissions, updates, time, and AppArmor or SELinux. Each control reports pass, fail, not applicable or not checked, with its evidence, why it matters and how to fix it. Like every check, it only runs fixed, read-only commands; from `/etc/shadow` it reads only account names and whether a password is set. Scans can include it on its own too.
- **The grade:** a score weighted by each control's severity, then capped by anything that should stop a handover: malware (F), changed system files (D), fixable critical vulnerabilities or a failed critical control (C), fixable high vulnerabilities (B). The audit page says what holds the grade back and what couldn't be checked.
- **Accepted risks:** admins accept a failed control's risk with a reason, for one host or every host, until an expiry date or indefinitely. It shows as accepted, leaves the score, and is recorded in the audit log.
- A **Server audits** page lists every audit with its grade. An admin switch there, **Audit new machines when they enroll**, audits each machine as soon as its agent enrolls.
- `deaconguard audit HOST_ID [--advanced] [--json]` and `deaconguard audit --local` print the grade, what holds it back and the failed controls with their fixes.

### Changed

- Audits are kept until someone deletes them; they don't count towards the 10 scans each host keeps.
- Audits and the hardening check need the agent 0.12.0 or later. Scans, schedules and audits asking an older agent for it are refused with the upgrade command.
- **Upgrading:** the database gains audits and accepted risks (schema 12).

### Fixed

- The audit log now names role changes, which 0.11.0 listed by their internal name.

## [0.11.0] - 2026-10-11

### Added

- **Roles: Admin, Operator and Viewer.** Viewers see hosts, findings, schedules and logs but change nothing. Operators also scan, answer sudo prompts, delete scans, change a host's sudo setting, manage schedules and download the log. Admins also enroll and remove machines, manage accounts, require two-step sign-in, and read the audit log. The server checks the role on every request, and the dashboard hides what a role can't use; viewers don't get sudo prompts.
- On the **Accounts** page, new accounts get a role (Viewer unless you choose otherwise), and a **Manage** menu per account changes its role, sets a temporary password, resets two-step sign-in, or disables or removes it. Changing a role signs the account out, so the new role applies at once. The last admin that can sign in can't be demoted, disabled or removed.
- `deaconguard user add NAME --role admin|operator|viewer` and `deaconguard user role NAME ROLE`; `user list` shows roles.
- **An agent-only port.** `deaconguard setup server --agent-listen 0.0.0.0:8444` (also an install script option and a `serve` option) gives agents a port that serves only the agent API, with no dashboard or sign-in page, so you can open it to every machine's network and keep 8443 for people. Setup remembers it; `--agent-listen off` removes it.
- **Agents move to the agent port by themselves.** Agents from 0.11.0 on 8443 are told about the agent port at their next check-in; each checks that the new port reaches the same server, with the same pinned key, then saves the new address and uses it. An agent that can't reach the new port stays on 8443, says why in its log, and tries again an hour later. The server's own agent stays on `127.0.0.1`. Older agents keep working on 8443 until they are upgraded. New enrollment tokens point at the agent port.
- The **Agents** page shows the port each agent uses and, with an agent port, how many have moved, which haven't and why, and when it is safe to limit the dashboard's port to your administrators.
- **Light, dark and system modes, and five themes.** System follows your computer's setting as it changes. Themes: Indigo (the default), Ocean, Teal, Plum and Graphite; severity colors never change. Pick them at the bottom of the sidebar or on **My account**. On a server the choice is saved to your account and follows you to every browser.

### Changed

- **Upgrading:** the database gains roles and a saved appearance (schema 11). Every existing account becomes an admin, so nobody loses access. Nothing else changes until you set roles or an agent port.
- The page loads `appearance.js` first, so it never flashes the wrong colors.
- The agent service may now write `/etc/deaconguard`, where it saves its new address after moving; the rest of `/etc` stays read-only to it.

## [0.10.0] - 2026-10-11

### Added

- **Two-step sign-in.** After the password, the dashboard asks for a 6-digit code from an authenticator app, so a stolen password alone can't sign in. Any app with time-based codes (TOTP) works: Google or Microsoft Authenticator, Bitwarden, 1Password, Proton Pass, Apple Passwords, Ente Auth, 2FAS, Aegis and others. Setup shows a QR code and the key, and ends with 10 one-time **recovery codes** for a lost phone. A code works once.
- **A reminder until it is on.** Every page shows a banner while your account has no two-step sign-in, and the sidebar marks your account; hiding the banner lasts until the next sign-in. With 2 or fewer recovery codes left, it reminds you to create new ones.
- **Require two-step sign-in** for every account, on the new **Accounts** page. Anyone without it sets it up right after signing in, before using the dashboard. It can only be turned on once your own account has it.
- **My account:** change your password, set up two-step sign-in, move it to a new phone, create new recovery codes or turn it off, and see every session signed in to your account, with its browser, address and last use; sign out one, or all others.
- **Accounts** page for admins: every account with its two-step sign-in status and last sign-in. Create an account with a temporary password, which the person must change at their first sign-in; set a new temporary password; reset two-step sign-in for a lost phone; disable, enable or remove an account. You change your own account on My account, so you can't lock yourself out, and the last account that can sign in can't be disabled or removed.
- `deaconguard user mfa-reset USERNAME`, for a lost phone when no other admin can reset it. `deaconguard user list` shows two-step sign-in status, recovery codes left, disabled accounts and temporary passwords.
- Every account change is recorded in the audit log, and sign-ins say whether they used the authenticator app or a recovery code.
- New docs: [Accounts and sign-in](https://docs.deaconguard.io/usage/accounts) and [Securing the dashboard](https://docs.deaconguard.io/security/securing-the-dashboard): keep port 8443 off the internet with a firewall, VPN, Tailscale, an SSH tunnel, AWS Systems Manager or an identity-aware proxy.

### Changed

- **Upgrading:** the database gains two-step sign-in, account and session fields (schema 10). Existing accounts and sessions keep working; two-step sign-in is off until each account turns it on.
- Changing your password signs out your other sessions. A disabled account is signed out and can't sign in.
- There is still no password reset by email, on purpose: another admin resets access, or the command line on the server.

### Fixed

- On narrow screens, a table with a screen-reader-only column heading could widen the whole page.

## [0.9.2] - 2026-10-11

### Fixed

- On the **Hosts** page, the **This server** label now sits beside the host name, as on the Agents page. A host with many check results made the Findings column wide and pushed the label onto the next line.
- A table wider than the screen scrolls inside its card instead of widening the whole page.

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

[Unreleased]: https://github.com/Cloudopsshell/deaconguard/compare/v0.15.0...HEAD
[0.15.0]: https://github.com/Cloudopsshell/deaconguard/compare/v0.14.0...v0.15.0
[0.14.0]: https://github.com/Cloudopsshell/deaconguard/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/Cloudopsshell/deaconguard/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/Cloudopsshell/deaconguard/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/Cloudopsshell/deaconguard/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/Cloudopsshell/deaconguard/compare/v0.9.2...v0.10.0
[0.9.2]: https://github.com/Cloudopsshell/deaconguard/compare/v0.9.1...v0.9.2
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
