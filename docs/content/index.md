---
slug: /
sidebar_label: Overview
title: DeaconGuard documentation
description: What DeaconGuard is, what it checks, and how its server and agents work together.
---

DeaconGuard is a Linux security scanner. It finds vulnerable packages, tampered system files, signs of compromise and risky configuration on your Linux machines, and shows the results in a self-hosted dashboard.

It checks installed packages and the running kernel against each distribution's **own security data**: Canonical's OVAL feeds for Ubuntu, the Debian Security Tracker, the OVAL feeds of Red Hat, AlmaLinux, Oracle and SUSE, the errata of Rocky Linux and Fedora, and Amazon Linux's ALAS bulletins. It also tells you when a release no longer gets security fixes. Optional checks add [system file integrity, malware and compromise indicators, security configuration, and an antivirus scan with ClamAV, or ClamAV and YARA rules](./checks.md).

import ThemedImage from '@theme/ThemedImage';
import Link from '@docusaurus/Link';

<div className="dg-cards">
  <Link className="dg-card" to="/quick-start"><span className="dg-card-icon">01</span><div><strong>Quick start</strong><span>A server and your first agent in a few minutes.</span></div></Link>
  <Link className="dg-card" to="/installation/install-script"><span className="dg-card-icon">02</span><div><strong>Installation</strong><span>The install script, Docker Compose or Kubernetes.</span></div></Link>
  <Link className="dg-card" to="/architecture"><span className="dg-card-icon">03</span><div><strong>Architecture</strong><span>How the server, agents and certificate pinning fit together.</span></div></Link>
  <Link className="dg-card" to="/reference/cli"><span className="dg-card-icon">04</span><div><strong>CLI and API</strong><span>Scans, tokens and exports from scripts.</span></div></Link>
</div>

## How it works

One binary does two jobs, and they are kept apart on purpose:

- **Server:** the HTTPS dashboard, with server audits graded A to F, compliance views and branded PDF reports, sign-in (two-step with any authenticator app), Admin, Operator and Viewer roles, and an audit log. It stores results and checks packages against the advisories. It faces the network, so it runs **without root**, as the `deaconguard` user.
- **Agent:** runs on each machine to scan, **as root**, so every check sees everything. It listens on nothing: it enrolls once with a token, then connects **out** to the server, runs the scans the server asks for and sends back the results. Scanned machines need no open ports and no internet access.

**The server never scans anything itself.** Every machine, the server's own included, is scanned by its own agent. The [install script](./installation/install-script.md) gives the server's machine an agent too, and the dashboard shows it as **This server**.

<div className="architecture-figure">
  <ThemedImage
    alt="The server runs without root and serves the dashboard. Every machine, the server's own included, runs an agent as root that asks the server for work and sends back results. The server downloads the distributions' advisories."
    sources={{ light: '/img/architecture-light.svg', dark: '/img/architecture-dark.svg' }}
  />
</div>

<div className="full-width-table">

| Component | Runs as | Listens on | Reaches |
| --- | --- | --- | --- |
| `deaconguard-server` | the `deaconguard` user, no root | `0.0.0.0:8443` (HTTPS) | the distributions' advisory feeds |
| `deaconguard-agent` | root | nothing | only its server |

</div>

Why they are split, and how they trust each other: [Architecture](./architecture.md).

For a single machine, [local mode](./usage/local-mode.md) gives you a dashboard on `127.0.0.1` without any accounts.

## Principles

- **Read-only.** Every command DeaconGuard runs on a machine is a fixed, read-only string in its source code. Scans never install software or change the system; the only third-party engines they run are ClamAV and YARA-X, for the antivirus scan. The install script installs them and the other tools the checks use, once.
- **Honest results.** A skipped, partial or failed check is never shown as clean, and missing or stale advisory data is never reported as "no vulnerabilities".
- **The server decides.** Agents send the package list; the server evaluates it against the advisories. A modified agent can lie about its check results, but it cannot hand the server its own vulnerability verdicts.
- **Self-hosted and open source.** You run the server, and your results stay with you. DeaconGuard is MIT licensed, and every release is [signed with Sigstore](./security/verify-a-release.md).

## Where to go next

- [Quick start](./quick-start.md): a server and a first agent in a few minutes.
- [Installation](./installation/install-script.md): every install option, upgrades and uninstalling.
- [Architecture](./architecture.md): how the server, agents and certificate pinning fit together.
