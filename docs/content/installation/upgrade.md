---
title: Upgrade
description: Upgrade DeaconGuard servers and agents.
---

Check the installed version with `deaconguard version`, and read the [changelog](https://github.com/Cloudopsshell/deaconguard/blob/main/CHANGELOG.md) for what changed; any upgrade steps are listed there. [Back up](../usage/backup-and-restore.md) the server's data before upgrading across a minor version, for example from 1.0.x to 1.1.0. Installs of 0.x upgrade to 1.0 the same way.

**Upgrade the server first, then its agents.** An agent from the previous release keeps working with a newer server while you upgrade.

**Upgrading an install-script server to 1.9.0** gives agents their own port, 8444, unless you had chosen one or `--agent-listen off`, or something else uses 8444. Port 8443 keeps answering agents. Each agent moves to 8444 by itself once it can reach it; until your firewall allows 8444 from your machines, they stay on 8443 and keep working. See [Give agents their own port](../security/securing-the-dashboard.md#give-agents-their-own-port). To keep one port: `sudo deaconguard setup server --agent-listen off`.

| Installed with | Upgrade |
| --- | --- |
| Install script | Run `curl -fsSL https://get.deaconguard.io \| sudo sh -` again on the server, then on each agent. On an enrolled agent it upgrades the agent and keeps its enrollment. For a specific release: `curl -fsSL https://get.deaconguard.io \| DEACONGUARD_VERSION=@RELEASE@ sudo -E sh -`. |
| `.deb` / `.rpm` | Repeat the [manual install](./manual-install.md) steps with the new `VERSION`. |
| Archive | Repeat the archive steps; they replace `/usr/local/bin/deaconguard`. |

## Docker Compose

Change the image tag in `compose.yaml` to the new version, then:

```bash
docker compose pull && docker compose up -d
```

Do the same with `--profile agent` if you run the agent.

## Helm

Upgrade the server's release, then the agents':

```bash
VERSION=$(curl -fsSL https://get.deaconguard.io/stable.txt)   # or the release you want
helm upgrade deaconguard oci://ghcr.io/cloudopsshell/charts/deaconguard --version "$VERSION" -n deaconguard --reuse-values
helm upgrade deaconguard-agent oci://ghcr.io/cloudopsshell/charts/deaconguard --version "$VERSION" -n deaconguard-agent --reuse-values
```

## Kustomize

Apply the new release's manifests (`?ref=v@RELEASE@` for the latest, as in [Kubernetes](./kubernetes.md)), or change `newTag` in your overlay and apply it.

## What happens

Upgrading the package restarts the running `deaconguard-server` and `deaconguard-agent` services. The new version upgrades the database on its first start; scans that were running are marked as interrupted.

:::warning No downgrades
Once a newer version has upgraded the database, an older version cannot open it. To go back, restore the backup you took before the upgrade.
:::
