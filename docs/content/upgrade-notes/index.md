---
title: Upgrade notes
description: What changed in each DeaconGuard release, and what to do when you upgrade to it, by install method.
---

One page per release, newest first: what's new, what to do before you upgrade, and anything particular to Kubernetes, the install script and Docker Compose, and known issues. The steps to upgrade are the same for every release: see [Upgrade](../installation/upgrade.md).

**Upgrading across several releases?** Read the page of every release between yours and the new one: from 1.7.0 to 1.9.2, the pages for 1.8.0 to 1.9.2. You can upgrade straight to the newest release; you don't need to install each one in turn.

Releases with nothing to do say so. The last 10 minor lines (now 1.0 to 1.9) are here; the [changelog](https://github.com/Cloudopsshell/deaconguard/blob/main/CHANGELOG.md) has every release, and its notes for older ones.

| Release | Released | What to do |
| --- | --- | --- |
| [1.9.2](./v1-9/v1-9-2.md) | 2026-10-24 | Nothing; Helm `--reuse-values` works again |
| [1.9.1](./v1-9/v1-9-1.md) | 2026-10-23 | Nothing (documentation only) |
| [1.9.0](./v1-9/v1-9-0.md) | 2026-10-23 | Allow port 8444 from your machines |
| [1.8.1](./v1-8/v1-8-1.md) | 2026-10-23 | Pipelines with `--fail-on`: end-of-life images now fail |
| [1.8.0](./v1-8/v1-8-0.md) | 2026-10-22 | Upgrade the server before the agents |
| [1.7.0](./v1-7/v1-7-0.md) | 2026-10-20 | Back up: database schema 26 |
| [1.6.0](./v1-6/v1-6-0.md) | 2026-10-20 | Back up: database schema 24 |
| [1.5.0](./v1-5/v1-5-0.md) | 2026-10-19 | Back up: database schema 23 |
| [1.4.0](./v1-4/v1-4-0.md) | 2026-10-19 | Nothing |
| [1.3.0](./v1-3/v1-3-0.md) | 2026-10-19 | Back up: database schema 22 |
| [1.2.0](./v1-2/v1-2-0.md) | 2026-10-18 | Upgrade agents for the Running containers check |
| [1.1.0](./v1-1/v1-1-0.md) | 2026-10-18 | Server first; the server needs `api.osv.dev` |
| [1.0.2](./v1-0/v1-0-2.md) | 2026-10-18 | Nothing |
| [1.0.1](./v1-0/v1-0-1.md) | 2026-10-17 | Nothing |
| [1.0.0](./v1-0/v1-0-0.md) | 2026-10-17 | From 0.x: back up, server first |
