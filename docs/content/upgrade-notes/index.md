---
title: Upgrade notes
description: What changed in each DeaconGuard release, and what to do when you upgrade to it, by install method.
---

One page per release, newest first: what's new, what to do before you upgrade, and anything particular to Kubernetes, the install script and Docker Compose, and known issues. The steps to upgrade are the same for every release: see [Upgrade](../installation/upgrade.md).

**Upgrading across several releases?** Read the page of every release between yours and the new one: from 1.17.0 to 1.18.0, the pages for 1.17.1 and 1.18.0. You can upgrade straight to the newest release; you don't need to install each one in turn.

Releases with nothing to do say so. The last 10 minor lines (now 1.11 to 1.20) are here; the [changelog](https://github.com/Cloudopsshell/deaconguard/blob/main/CHANGELOG.md) has every release, and its notes for older ones.

| Release | Released | What to do |
| --- | --- | --- |
| [1.20.0](./v1-20/v1-20-0.md) | 2026-10-31 | Upgrade the cluster agent too; the server reaches your images' registries |
| [1.19.0](./v1-19/v1-19-0.md) | 2026-10-31 | Upgrade the agents to scan containers for malware |
| [1.18.0](./v1-18/v1-18-0.md) | 2026-10-30 | Back up: database schema 28 |
| [1.17.1](./v1-17/v1-17-1.md) | 2026-10-30 | Nothing; Kubernetes health checks leave the access log |
| [1.17.0](./v1-17/v1-17-0.md) | 2026-10-29 | Small servers: check the memory for parsed feeds |
| [1.16.0](./v1-16/v1-16-0.md) | 2026-10-29 | Nothing; slow requests and high CPU are now logged |
| [1.15.0](./v1-15/v1-15-0.md) | 2026-10-29 | Allow `gitlab.com` if outbound traffic is limited and you watch GitLab |
| [1.14.0](./v1-14/v1-14-0.md) | 2026-10-29 | Allow `hub.docker.com` and `api.github.com` if outbound traffic is limited |
| [1.13.0](./v1-13/v1-13-0.md) | 2026-10-29 | Nothing; watches order tags by build time |
| [1.12.0](./v1-12/v1-12-0.md) | 2026-10-29 | Back up: database schema 27; ECR browsing needs two more IAM actions |
| [1.11.1](./v1-11/v1-11-1.md) | 2026-10-25 | Allow `raw.githubusercontent.com` if outbound traffic is limited |
| [1.11.0](./v1-11/v1-11-0.md) | 2026-10-25 | Nothing; new optional Helm settings for Traefik |
