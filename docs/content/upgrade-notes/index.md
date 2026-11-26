---
title: Upgrade notes
description: What changed in each DeaconGuard release, and what to do when you upgrade to it, by install method.
---

One page per release, newest first: what's new, what to do before you upgrade, and anything particular to Kubernetes, the install script and Docker Compose, and known issues. The steps to upgrade are the same for every release: see [Upgrade](../installation/upgrade.md).

**Upgrading across several releases?** Read the page of every release between yours and the new one: from 1.20.0 to 1.21.0, the pages for 1.20.1, 1.20.2, 1.20.3 and 1.21.0. You can upgrade straight to the newest release; you don't need to install each one in turn.

Releases with nothing to do say so. The last 10 minor lines (now 1.27 to 1.36) are here; the [changelog](https://github.com/Cloudopsshell/deaconguard/blob/main/CHANGELOG.md) has every release, and its notes for older ones.

| Release | Released | What to do |
| --- | --- | --- |
| [1.36.0](./v1-36/v1-36-0.md) | 2026-11-26 | Nothing to do. Upgrade the agents on hosts with Linux 4.18 to 5.7 for live detection there; with Helm, set `agent.olderKernels` for such nodes |
| [1.35.0](./v1-35/v1-35-0.md) | 2026-11-18 | Nothing to do. Pipelines: pin the GitHub action to `v1.35.0` for the run summary, and for a refused code scanning upload to be a warning |
| [1.34.0](./v1-34/v1-34-0.md) | 2026-11-16 | Nothing to do. The server now asks get.deaconguard.io once a day for the newest release's number; turn that off in Settings if you don't want it |
| [1.33.1](./v1-33/v1-33-1.md) | 2026-11-15 | Nothing to do. New contact addresses and updated libraries |
| [1.33.0](./v1-33/v1-33-0.md) | 2026-11-08 | Back up: database schema 35. Upgrade the agents for container names and allowlist rules skipped before the rate limit |
| [1.32.0](./v1-32/v1-32-0.md) | 2026-11-06 | Nothing to do. Upgrade the agents for live detection's privilege, kernel module and ptrace rules |
| [1.31.0](./v1-31/v1-31-0.md) | 2026-11-05 | Nothing to do. A new server scans itself once; the scan dialog ticks the recommended checks |
| [1.30.0](./v1-30/v1-30-0.md) | 2026-11-05 | Back up: database schema 34. Upgrade the agents for live detection's network rules |
| [1.29.0](./v1-29/v1-29-0.md) | 2026-11-02 | Nothing to do. A cluster's nodes' vulnerabilities count once, so the dashboard's numbers go down for clusters |
| [1.28.0](./v1-28/v1-28-0.md) | 2026-11-02 | Back up: database schema 33. A Kubernetes cluster is managed as one: node settings move to the cluster, which turns on for all its nodes what was on for any; schedules naming a node now name its cluster |
| [1.27.0](./v1-27/v1-27-0.md) | 2026-11-01 | Back up: database schema 32. Live detection is off until you turn it on; upgrade the agents, and the Helm chart or Kustomize base for the node agent's new capabilities, to use it |
