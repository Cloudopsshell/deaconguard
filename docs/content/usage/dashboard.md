---
title: Dashboard
description: What the DeaconGuard dashboard shows.
---

The server serves the dashboard over HTTPS with sign-in, optionally [with two-step sign-in](./accounts.md#two-step-sign-in); [local mode](./local-mode.md) serves the same dashboard on `127.0.0.1` without sign-in. The CLI and the dashboard share the same data.

## Pages

- **Dashboard:** hosts, hosts on a release [past regular support](../supported-distributions.md#release-lifecycle), what to fix now, [known exploited](./vulnerabilities.md) vulnerabilities, the most exposed hosts, a chart of open vulnerabilities over time, the other checks' results, and the top vulnerabilities.
- **Hosts:** every machine with an agent, the server's own (marked **This server**) included, with its latest results per check, an **End of life** or **Extended support** badge when its release needs one, a severity overview, known exploited vulnerabilities and its [tags](./vulnerabilities.md#host-tags), which filter the list. Scan or remove hosts here; add machines with **Enroll a machine**. In [local mode](./local-mode.md), **Add this machine** registers the machine DeaconGuard runs on.
- **Host page:** its tags, per-check results, full scan reports with search and filters, its vulnerabilities over time, the host's audits, and the scan history. **Run audit** starts a [server audit](./audits.md).
- **Server audits:** every audit with its grade, and the switch to audit machines as they enroll. Audit and scan pages have **Reports**: create, download (PDF, HTML, Excel, CSV, JSON) and share them; see [Reports](./reports.md). **Verify a report** checks a report's fingerprint. Each audit's page has the grade, what holds it back, every baseline control with how to fix it, accepted risks and the machine's inventory. See [Server audits](./audits.md).
- **Vulnerabilities:** each vulnerability, with its CVSS score and exploitation, most urgent first, and the hosts it affects. See [Vulnerabilities and what to fix first](./vulnerabilities.md).
- **Images:** container images in registries, checked without running them, with each one's results and scan history, and registry logins for private images (admins). See [Images in registries](./images.md).
- **Network:** networks and names the server scans on a schedule for open ports, exposed services, TLS problems and web site problems, with each target's latest result and history. See [TLS, network and web checks](./network.md#in-the-dashboard).
- **Agents** (server only): enrolled agents, their status and the server port each uses, and enrollment tokens. With an [agent port](../security/securing-the-dashboard.md#give-agents-their-own-port), it shows which agents have moved to it.
- **Schedules:** automatic scans on chosen days. See [Schedules](#schedules).
- **Logs:** what the server and each agent did. See [Logs](#logs).
- **Audit log** (server only, admins): sign-ins, account changes, tokens, enrollments, scans and removals.
- **Accounts** (server only, admins): everyone who can sign in, their role, two-step sign-in status and last sign-in; create accounts, and change roles, reset, disable and remove them. See [Accounts and sign-in](./accounts.md#managing-accounts).
- **Settings** (admins): [fix deadlines](./vulnerabilities.md#fix-deadlines); [single sign-on](./single-sign-on.md) with your identity provider; your company's name, contact line and logo for [reports](./reports.md#your-companys-branding); **Notifications**: email, Slack, Teams and webhook channels, see [Notifications](./notifications.md); and **Policies**: your own controls for every audit, in YAML. See [Policies](./policies.md).
- On an audit's page, **Compliance** reads the audit for NIST SP 800-53, PCI DSS, HIPAA, ISO/IEC 27001 and the DISA STIG for the machine's operating system. See [Compliance](./compliance.md).
- **My account** (server only, your name at the bottom of the sidebar): your role, password, two-step sign-in, recovery codes, appearance and sessions. See [My account](./accounts.md#my-account).

On a server, what you can do depends on your [role](./accounts.md#roles): viewers see everything but change nothing, operators also scan and manage schedules, and admins also enroll and remove machines and manage accounts. Buttons your role can't use are hidden.

## Appearance

Choose light, dark, or **System**, which follows your computer's setting as it changes, with the buttons at the bottom of the sidebar. **Theme** picks one of five color themes: Indigo (the default), Ocean, Teal, Plum and Graphite. Severity colors stay the same in every theme, so a red finding is always critical. On a server the choice is saved to your account and follows you to every browser; the local dashboard keeps it in the browser.

## Live scans

While a scan runs, the host's page shows a live console: each step, every fixed command DeaconGuard runs (marked when it goes through sudo), how long each took, and findings as each check completes. It never shows command output or credentials.

Each scan's activity log is saved with its results, so **View logs** in the scan history replays it later.

## History

Scan history keeps the 10 most recent scans per host, plus any older scan that still holds a check's latest result. Audits are kept until someone deletes them. Each scan can be deleted.

## Schedules

The **Schedules** page scans hosts automatically, so results stay current without anyone pressing **Scan now**. A schedule has:

- **days and a time**: every day, weekdays, or any days of the week, at a time in a time zone of your choice. Daylight saving changes are handled, and a schedule runs once per day even when the clocks go back.
- **hosts**: all hosts, including hosts added later, or chosen hosts.
- **checks**: any of the checks, including the advanced antivirus scan.

The server starts each run's scans just as Scan now would. It skips a host that is already being scanned, or whose agent is too old for a chosen check, and the [Logs](#logs) page says why. If the server was stopped when a run was due, the run happens once when it starts again.

Schedules run **with root privileges** by default, so every check sees everything: every machine, the server's own included, is scanned by its agent as root. A schedule can turn root off, and the dialog then reminds you that results will show partial coverage.

A [maintenance window](./notifications.md#maintenance-windows), on the same page, can skip scheduled scans of hosts being patched.

**Run now** starts a schedule's scans at once; **Turn off** pauses it without deleting it. Each host's page shows its next scheduled scan, and the dashboard flags hosts whose latest results are more than 7 days old. The audit log records changes to schedules, and names the schedule that started each scan.

## Logs

The **Logs** page shows what happened, newest first, so you don't need SSH and `journalctl` to find out why a scan failed or an agent went quiet.

- **From the server:** starts and stops, with why the previous run ended (a reboot, running out of memory, a crash); agents connecting and no longer checking in; enrollments; each scan's start (and by whom), finish and failure; and every warning and error a scan reported, such as a stale advisory feed or a skipped check.
- **When the server is busy:** a request that takes more than 2 seconds, as `Slow request: GET /api/summary took 12s (status 200); the server used 11.8s of CPU meanwhile`, at most once every 5 minutes for each page; and when the server keeps more than one CPU core busy for 30 seconds, `High CPU: the server used 3.4 cores for the last 30s. Busy in: …`, naming the parts of DeaconGuard's code the time went to and the requests in progress, at most once every 10 minutes. These lines go to the server's standard output too, so `kubectl logs` and `journalctl` show them.
- **On standard output,** every server line starts with its level, `INFO`, `WARNING` or `ERROR`, and the server prints only what happens: a quiet server prints nothing after starting. To see each request as well, turn on the access log: `--access-log`, `DEACONGUARD_ACCESS_LOG=1`, or the Helm value `server.accessLog: true`. Its `ACCESS` lines go to standard output only, not to this page; routine polls and Kubernetes health checks are left out unless they fail.
- **From each agent** (0.6.0 or later): the agent's own log, sent to the server over its existing connection. Lines from while the server was unreachable, such as "Cannot reach the server", are kept on the agent and arrive once it answers again, with their original times.

Filter by server or agents, machine, level and text; the filters are part of the page's address, so a filtered view can be shared. **Follow** shows new entries as they arrive; **Download** saves the filtered entries as a text file. Each host's page shows its latest entries, with a link to the full log.

**CPU profile (30 s)**, for admins, records what the server spends its CPU on for 30 seconds while it is busy, and downloads it as a `.pprof` file, to open with `go tool pprof` or attach to a bug report. Taking one is recorded in the audit log.

Entries are kept for 7 days, at most 100,000. Reading the log needs a signed-in account; downloads are recorded in the audit log, and so is viewing, at most once per account every 15 minutes. The services' journals still have everything as well.

## Sudo passwords

Operators and admins answer these; viewers never see them. When a [check needs sudo](../checks.md#running-checks-with-sudo) and sudo asks for a password, the scan pauses and the browser asks for it. The answer goes to that one scan, is kept in memory only, and is never saved or logged. A wrong password can be retried up to three times. Closing the dialog continues the scan without sudo; an unanswered question stops the scan after 10 minutes.
