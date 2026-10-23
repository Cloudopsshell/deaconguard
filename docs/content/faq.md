---
title: FAQ
description: Common questions about DeaconGuard.
---

### Does DeaconGuard change anything on the machines it scans?

Scans don't. Every command a scan runs is a fixed, read-only string in DeaconGuard's source: scans never install software, change configuration or delete files. The only third-party programs a scan runs are ClamAV and YARA-X, for the antivirus scan.

Installing is separate: the [install script](./installation/install-script.md) installs DeaconGuard and the tools its checks use (ClamAV, YARA-X, procps, iproute2, findutils, and cosign to verify the release), once, and tells you what it installed.

### Should I use the basic or the advanced antivirus scan?

Basic (ClamAV) is the default and finds known malware by signature. Advanced adds YARA rules, which are better at webshells, crypto miners and attacker tools, especially new variants; it takes a few more minutes and can occasionally flag a harmless file, so look at a match before acting. Web servers and other machines exposed to the internet benefit most. See [the advanced antivirus scan](./checks.md#the-advanced-antivirus-scan).

### How much does ClamAV need?

About 110 MB of disk for its signatures, which `clamav-freshclam` keeps current in the background. A scan with ClamAV needs about 1.5 GB of free memory and swap, because ClamAV loads all its signatures; on smaller machines the antivirus check is skipped and says so, and the other checks run as usual.

### Why does the agent run as root?

A security scanner has to see every process, every system file and the firewall rules. Without root, the deeper checks only have partial coverage, and say so. The agent opens no ports; it only connects out to your server.

### Should the dashboard be reachable from the internet?

No. Allow port 8443 only from your own networks (and the agent port, 8444, only from your machines' networks) and reach the dashboard over a VPN, Tailscale, an SSH tunnel or a similar private path, and turn on two-step sign-in. See [Securing the dashboard](./security/securing-the-dashboard.md).

### Can I give someone read-only access?

Yes: give them the **Viewer** role. They see every host, finding, schedule and log, but can't start scans or change anything; **Operator** adds scanning and schedules. See [Roles](./usage/accounts.md#roles).

### Is there a dark mode?

Yes: light, dark, or System, which follows your computer, plus five color themes. Use the buttons at the bottom of the sidebar, or **My account → Appearance**. See [Appearance](./usage/dashboard.md#appearance).

### If I turn on the agent port, do my agents stop working?

No. The agent port is added next to 8443, which keeps answering agents. Agents from 0.11.0 move to the agent port by themselves, after checking it reaches the same server; older ones keep using 8443 until you upgrade them. Only close 8443 to your machines once the **Agents** page says every agent has moved. See [Give agents their own port](./security/securing-the-dashboard.md#give-agents-their-own-port).

### Which authenticator apps work for two-step sign-in?

Any app that supports time-based codes (TOTP): Google Authenticator, Microsoft Authenticator, Bitwarden, 1Password, Proton Pass, KeePassXC, Apple Passwords, Ente Auth, 2FAS, Aegis and others. See [Two-step sign-in](./usage/accounts.md#two-step-sign-in).

### I lost my phone. How do I sign in?

Use one of your recovery codes: on the sign-in page, choose **Use a recovery code**. Then set up your new phone on **My account**. Without recovery codes, another admin can reset your two-step sign-in on the **Accounts** page; if you are the only admin, run `sudo -u deaconguard deaconguard user mfa-reset NAME` on the server.

### I forgot my password. Is there a reset link?

No; DeaconGuard sends no email. Another admin sets a temporary password for you on the **Accounts** page, and you choose a new one when you sign in. If you are the only admin, run `sudo -u deaconguard deaconguard user passwd NAME` on the server. See [When someone loses access](./usage/accounts.md#when-someone-loses-access).

### Do scanned machines need internet access?

Only to download the package at install time. After that, an agent only talks to your server; the server fetches the advisory data.

### Why is the server's certificate self-signed? Is that safe?

Agents trust the server by its key fingerprint, which comes with the enrollment token, so they don't depend on a certificate authority. Your browser warns once; check the fingerprint that setup printed. You can also use your own certificate. See [Architecture](./architecture.md#certificate-pinning).

### Can I scan Rocky Linux, AlmaLinux or CentOS Stream?

Not yet. DeaconGuard only scans distributions whose official advisory data it can use accurately; see [Supported distributions](./supported-distributions.md).

### Which vulnerabilities should I fix first?

Those [known to be exploited](./usage/vulnerabilities.md): DeaconGuard checks every vulnerability against CISA's Known Exploited Vulnerabilities catalog and FIRST's EPSS, and lists known exploited ones first, then those likely to be exploited, then by severity. The dashboard's **Known exploited** tile opens them.

### Can DeaconGuard email me, or post to Slack or Teams?

Yes: add a channel under **Settings → Notifications** for email, Slack, Microsoft Teams or any webhook, and choose its events, such as newly exploited vulnerabilities, malware, failed scans, offline agents, or a daily or weekly digest. See [Notifications](./usage/notifications.md).

### Can I script DeaconGuard, or connect it to our SIEM or ticketing?

Yes. Scripts and CI pipelines use the [API](./reference/api.md) with an API token. Notifications go to syslog, Splunk, Jira and ServiceNow as well as email, Slack, Teams and webhooks; see [Notifications](./usage/notifications.md).

### Can I run DeaconGuard in Docker or Kubernetes?

Yes. The server runs from the image `ghcr.io/cloudopsshell/deaconguard` with [Docker or Compose](./installation/docker.md), or in [Kubernetes](./installation/kubernetes.md) with the Helm chart or Kustomize, and an agent DaemonSet scans every node with one [reusable token](./usage/agents.md#reusable-tokens).

### Can I scan containers?

Not their contents yet. Reports cover the host's DPKG or RPM packages and its running kernel, not software inside container images; an agent running in a container scans its host, not itself.

### How do I check a new server before handing it over?

Run a [server audit](./usage/audits.md): open the host and choose **Run audit**. It runs every check and the 72-control hardening baseline, and grades the server from A to F, with what holds the grade back and how to fix each failed control. To have it ready without asking, turn on **Audit new machines when they enroll** on the **Server audits** page.

### How do I give a client a report of their server?

Open the server's audit and choose **Create report**, with the client's name. Download the PDF, which carries your company's name and logo (set them once under **Settings**), or share a link that works for up to 30 days. See [Reports](./usage/reports.md).

### Does a good audit make a server PCI DSS, HIPAA or ISO 27001 compliant?

No. The [Compliance](./usage/compliance.md) view shows which of a framework's requirements the audit gives evidence for, and whether they're met on that server. Frameworks also require policies, people and processes no scan can see, and an assessor decides compliance. The audit is useful evidence for them.

### Can I check our own rules too?

Yes: add a [policy](./usage/policies.md) in YAML under **Settings → Policies**, for example that a monitoring agent runs or a port stays closed. Every audit tests it next to the baseline.

### Does DeaconGuard check my applications' libraries?

Yes, from 1.1.0: the **Application libraries** check finds npm, Python, Go, Ruby, Rust and PHP libraries and checks them against OSV. Only the server contacts OSV, and it sends only library names and versions. Every scan can also be downloaded as an SBOM (CycloneDX or SPDX). See [Application libraries and SBOM](./usage/libraries-and-sbom.md).

### Does a clean report mean my machine is secure?

No. It means DeaconGuard found nothing in what it checked. Checks that couldn't run, or couldn't run fully, are marked as such and never shown as clean.

### How do I scan from cloud-init or Ansible?

Create a token, then run the install command with `DEACONGUARD_TOKEN` or `--token-file`. See [Agents](./usage/agents.md#automation).

### Is DeaconGuard free?

Yes. It is open source under the MIT license, and you host it yourself.
