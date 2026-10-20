---
title: Uninstall
description: Remove DeaconGuard and, optionally, its data.
---

```bash
sudo apt remove deaconguard          # Debian and Ubuntu
sudo dnf remove deaconguard          # RHEL and its rebuilds, Fedora, Amazon Linux
sudo zypper remove deaconguard       # openSUSE, SUSE Linux Enterprise
sudo rm /usr/local/bin/deaconguard   # archive install
```

On a Mac, stop the agent's daemon, then remove it and the binary:

```bash
sudo launchctl bootout system/io.deaconguard.agent
sudo rm /Library/LaunchDaemons/io.deaconguard.agent.plist /usr/local/bin/deaconguard
```

Removing the package stops the services and **keeps your data**. To delete it as well:

| Machine | Remove |
| --- | --- |
| Server | `/var/lib/deaconguard/` |
| Agent | `/etc/deaconguard/`, and on a Mac also `/var/log/deaconguard-agent.log` |
| Local mode | `~/.local/share/deaconguard/`, or the directory in `DEACONGUARD_HOME` |

Before uninstalling an agent, remove its host in the server's dashboard. That revokes the agent's credential on the server.

## Docker Compose

```bash
docker compose --profile agent down       # keeps the volumes
docker compose --profile agent down -v    # deletes the server's data and the agent's identity too
```

## Kubernetes

Revoke the agents' [reusable token](../usage/agents.md#reusable-tokens) first, then:

```bash
helm uninstall deaconguard-agent -n deaconguard-agent
helm uninstall deaconguard -n deaconguard
```

or `kubectl delete -k` the same Kustomize directories. The server's PersistentVolumeClaim, `data-deaconguard-0`, stays until you delete it, and each node keeps its agent's identity in `/var/lib/deaconguard-agent` until you remove that directory.
