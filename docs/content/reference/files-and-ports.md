---
title: Files and ports
description: Where DeaconGuard keeps its files, and the ports it uses.
---

## Ports

| Port | Who listens | Used by |
| --- | --- | --- |
| 8443/tcp | Server (HTTPS) | Browsers, and agents unless they have their own port |
| Your choice, such as 8444/tcp | Server (HTTPS), only with `--agent-listen`; serves the agent API alone | Agents |
| 7480/tcp | Local mode, on `127.0.0.1` only (HTTP) | Your browser on the same machine |

Agents listen on nothing.

## Files

| Path | What |
| --- | --- |
| `/usr/bin/deaconguard` | The binary (package install); `/usr/local/bin/deaconguard` for an archive install |
| `/var/lib/deaconguard/deaconguard.db` | Server database |
| `/var/lib/deaconguard/tls/` | Server certificate and key |
| `/var/lib/deaconguard/feeds/` | Cached advisory data |
| `/etc/deaconguard/agent.json` | Agent's server address, certificate pin and credential; root only |
| `/usr/lib/systemd/system/deaconguard-server.service` | Server service |
| `/usr/lib/systemd/system/deaconguard-agent.service` | Agent service |
| `/etc/systemd/system/deaconguard-server.service.d/10-setup.conf` | Settings saved by `deaconguard setup server` |
| `~/.local/share/deaconguard/` | Local mode data |

In the [container image](../installation/docker.md):

| Path | What |
| --- | --- |
| `/ko-app/deaconguard` | The binary, the image's entrypoint |
| `/home/nonroot/` | The server's data (`DEACONGUARD_HOME`), on a volume: the same files as `/var/lib/deaconguard/` |
| `/host` | The agent's view of the host's root filesystem, read-only |
| `/var/lib/deaconguard-agent/agent.json` | The agent's identity, on the host (Kubernetes) or the `agent` volume (Compose) |

## Services

```bash
sudo systemctl status deaconguard-server
sudo systemctl status deaconguard-agent
journalctl -u deaconguard-server
journalctl -u deaconguard-agent
```
