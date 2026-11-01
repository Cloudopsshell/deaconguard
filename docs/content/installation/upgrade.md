---
title: Upgrade
description: Upgrade DeaconGuard servers and agents, with the install script, packages, Docker Compose, Helm or Kustomize.
---

These steps are the same for every release. What a particular release changes, and anything to do before upgrading to it, is in its [upgrade notes](../upgrade-notes/index.md).

## Before you upgrade

1. **Check what you run:** `deaconguard version` on the server, or the version at the bottom of the dashboard's sidebar.
2. **Read the [upgrade notes](../upgrade-notes/index.md)** of every release between yours and the new one. Most need nothing; some ask you to open a port or upgrade agents.
3. **[Back up](../usage/backup-and-restore.md#back-up) the server's data.** A release can upgrade the database on its first start, and an earlier release can't open it afterwards (see [Going back to an earlier release](#going-back-to-an-earlier-release)).

**Upgrade the server first, then its agents.** An agent from an earlier release keeps working with a newer server while you upgrade, but a newer agent may send what an older server doesn't understand. You can go straight to the newest release; there's no need to install each one in between.

## Which agents to upgrade

From 1.23.0, the server compares each agent's version with its own:

- **Agents** page: the agent's version shows **Upgrade to 1.23.0**, and a note above the list says how many agents are older than the server, which checks they can't run until they're upgraded, and the command that upgrades them.
- **The host's page** of an older agent says the same for that host.
- **`deaconguard host list`** shows each agent's version, marks the older ones, and prints the command.
- **The agent's log:** an agent of 1.23.0 or later logs it once when the server is newer.

The command it shows is for agents installed with the install script, on a Linux machine or a Mac. For agents in Kubernetes, it says to upgrade their Helm release or Kustomize image tag instead. It can't tell an agent installed with packages or Docker Compose from one installed with the install script, so upgrade those as below. A development build of the server, whose version ends in `-dev`, doesn't compare.

## Install script and packages

| Installed with | Upgrade |
| --- | --- |
| Install script | Run `curl -fsSL https://get.deaconguard.io \| sudo sh -` again on the server, then on each agent. On an enrolled agent it upgrades the agent and keeps its enrollment. Settings given to setup earlier, such as `--agent-listen`, are kept. For a specific release: `curl -fsSL https://get.deaconguard.io \| DEACONGUARD_VERSION=@RELEASE@ sudo -E sh -`. |
| `.deb` / `.rpm` | Repeat the [manual install](./manual-install.md) steps with the new `VERSION`. |
| Archive | Repeat the archive steps; they replace `/usr/local/bin/deaconguard`. |

## Docker Compose

Change the image tag in `compose.yaml` to the new version, then:

```bash
docker compose pull && docker compose up -d
```

Do the same with `--profile agent` if you run the agent.

## Helm

Upgrade the server's release:

```bash
VERSION=$(curl -fsSL https://get.deaconguard.io/stable.txt)   # or the release you want
helm upgrade deaconguard oci://ghcr.io/cloudopsshell/charts/deaconguard --version "$VERSION" -n deaconguard --reset-then-reuse-values
```

Then, only if you installed the [agent DaemonSet](./kubernetes.md#3-the-agents) (or the cluster agent) as a release of its own, upgrade it the same way:

```bash
helm upgrade deaconguard-agent oci://ghcr.io/cloudopsshell/charts/deaconguard --version "$VERSION" -n deaconguard-agent --reset-then-reuse-values
```

`helm list -A` shows the releases you have.

- **`--reset-then-reuse-values`** (Helm 3.14 and later) keeps the settings you installed with, and takes every setting a newer chart adds from that chart. Use it for every upgrade.
- **Or keep your settings in a file:** `helm get values deaconguard -n deaconguard -o yaml > values.yaml` once, then upgrade with `-f values.yaml` instead. This suits settings kept in Git (Argo CD, Flux).
- **Not without either:** a `helm upgrade` with neither flag nor file drops your settings, such as the admin secret, for the chart's defaults.

**With Flux, Argo CD or a pipeline** that passes your values file, upgrading is changing the chart's version in Git or in the job: they render the new chart's defaults plus your values every time, so no flag is needed. See [With Flux, Argo CD or a pipeline](./kubernetes.md#with-flux-argo-cd-or-a-pipeline).

## Kustomize

Apply the new release's manifests (`?ref=v@RELEASE@` for the latest, as in [Kubernetes](./kubernetes.md)), or change `newTag` in your overlay and apply it.

## What happens

Upgrading restarts the server and the agents (the `deaconguard-server` and `deaconguard-agent` services, or their pods). The new release upgrades the database on its first start, if it needs to, and scans that were running are marked as interrupted. Agents reconnect by themselves.

## Going back to an earlier release

Once a newer release has upgraded the database, an earlier release can't open it, and won't start. Which releases change the database is in the [upgrade notes](../upgrade-notes/index.md) ("Back up: database schema …"). To go back:

1. Stop the server.
2. Install the earlier release, the same way you installed DeaconGuard.
3. [Restore](../usage/backup-and-restore.md#restore) the backup you took before upgrading.

Results from after the upgrade are lost; agents need no change. If the new release didn't change the database, installing the earlier release is enough.
