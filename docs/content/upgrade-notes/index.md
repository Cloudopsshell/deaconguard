---
title: Upgrade notes
description: What changed in each DeaconGuard release, and what to do when you upgrade to it, by install method.
---

One page per release, newest first: what's new, what to do before you upgrade, and anything particular to Kubernetes, the install script and Docker Compose, and known issues. The steps to upgrade are the same for every release: see [Upgrade](../installation/upgrade.md).

**Upgrading across several releases?** Read the page of every release between yours and the new one: from 1.20.0 to 1.21.0, the pages for 1.20.1, 1.20.2, 1.20.3 and 1.21.0. You can upgrade straight to the newest release; you don't need to install each one in turn.

Releases with nothing to do say so. The last 10 minor lines (now 1.18 to 1.27) are here; the [changelog](https://github.com/Cloudopsshell/deaconguard/blob/main/CHANGELOG.md) has every release, and its notes for older ones.

| Release | Released | What to do |
| --- | --- | --- |
| [1.27.0](./v1-27/v1-27-0.md) | 2026-11-01 | Back up: database schema 32; upgrade the agents, and the Helm chart or Kustomize base for the node agent's new capabilities |
| [1.26.0](./v1-26/v1-26-0.md) | 2026-11-01 | Back up: database schema 31; upgrade the agents and schedule the new Attack paths check to use it |
| [1.25.0](./v1-25/v1-25-0.md) | 2026-11-01 | Back up: database schema 30; tick web checks on existing network targets to use them |
| [1.24.0](./v1-24/v1-24-0.md) | 2026-11-01 | Nothing |
| [1.23.0](./v1-23/v1-23-0.md) | 2026-11-01 | Nothing; the Agents page then shows which agents to upgrade |
| [1.22.0](./v1-22/v1-22-0.md) | 2026-11-01 | Nothing; upgrade the agents and schedule the new Host changes check to use it |
| [1.21.0](./v1-21/v1-21-0.md) | 2026-10-31 | Back up: database schema 29; upgrade the cluster agent for the cluster's page |
| [1.20.3](./v1-20/v1-20-3.md) | 2026-10-31 | Nothing |
| [1.20.2](./v1-20/v1-20-2.md) | 2026-10-31 | Nothing; optionally move the chart's agents to one token |
| [1.20.1](./v1-20/v1-20-1.md) | 2026-10-31 | Nothing; run the node agent to avoid downloads |
| [1.20.0](./v1-20/v1-20-0.md) | 2026-10-31 | Upgrade the cluster agent too; the server reaches your images' registries |
| [1.19.0](./v1-19/v1-19-0.md) | 2026-10-31 | Upgrade the agents to scan containers for malware |
| [1.18.0](./v1-18/v1-18-0.md) | 2026-10-30 | Back up: database schema 28 |
