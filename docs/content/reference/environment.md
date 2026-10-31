---
title: Environment variables
description: Environment variables DeaconGuard and its install script read.
---

## Install script

| Variable | Effect |
| --- | --- |
| `DEACONGUARD_TOKEN` | Install an agent and enroll it with this token. The script passes it to setup through a private temporary file, never on a command line. |
| `DEACONGUARD_NAME` | With `DEACONGUARD_TOKEN`: the [name](../usage/agents.md#names) the dashboard shows the host as, instead of its hostname. |
| `DEACONGUARD_REGISTRY_USERNAME`, `DEACONGUARD_REGISTRY_PASSWORD` | A login for [`deaconguard image scan`](../usage/images.md#registries-and-logins): a username and a token or password with pull access to the image's registry. |
| `DEACONGUARD_REGISTRY` | The registry host that login is for, such as `registry.gitlab.com`. When it is set, the login is sent to that registry only, never to another, such as Docker Hub for a public image. The [GitLab template](../usage/ci-cd.md#gitlab-ci) sets it to `$CI_REGISTRY`. |
| `DEACONGUARD_VERSION` | Install this release, for example `@RELEASE@`, instead of the latest. |

Set them **after the pipe**, before `sudo -E`, which passes them on to the installer (as root, leave out `sudo -E`):

```bash
curl -fsSL https://get.deaconguard.io | DEACONGUARD_VERSION=@RELEASE@ DEACONGUARD_TOKEN=deaconguard1.… sudo -E sh -
```

## DeaconGuard

| Variable | Effect |
| --- | --- |
| `DEACONGUARD_HOME` | The data directory. Default: `/var/lib/deaconguard` for the server service, `~/.local/share/deaconguard` otherwise. |
| `DEACONGUARD_AGENT_CONFIG` | The agent's configuration file. Default: `/etc/deaconguard/agent.json` for root. |
| `DEACONGUARD_TOKEN` | Read by `deaconguard setup agent` when no `--token-file` is given. |
| `DEACONGUARD_NAME` | Read by `deaconguard setup agent` and `deaconguard agent enroll` when no `--name` is given, and by `deaconguard agent run` when it enrolls itself: the host's [name](../usage/agents.md#names) on the dashboard. |

## Containers

Read by the [container image](../installation/docker.md), and by DeaconGuard anywhere else they are set.

| Variable | Read by | Effect |
| --- | --- | --- |
| `DEACONGUARD_ADMIN_USER` | `serve` | Create this account, an admin, when the server has none. Ignored once any account exists. |
| `DEACONGUARD_ADMIN_PASSWORD_FILE` | `serve` | The file with that account's password, such as a secret; one trailing newline is ignored. |
| `DEACONGUARD_ADMIN_PASSWORD` | `serve` | The password itself, when there is no file. Prefer the file: the environment is easier to leak. |
| `DEACONGUARD_TRUSTED_PROXIES` | `serve` | Comma-separated addresses or networks of reverse proxies, like `--trusted-proxy`. See [Behind a reverse proxy](../security/securing-the-dashboard.md#behind-a-reverse-proxy). |
| `DEACONGUARD_ACCESS_LOG` | `serve` | `1` or `true` writes a line to standard output for each request, like `--access-log`. On a server installed with the install script, set it with `sudo systemctl edit deaconguard-server` (`[Service]` then `Environment=DEACONGUARD_ACCESS_LOG=1`); in Docker Compose, under the server's `environment`. |
| `DEACONGUARD_CLUSTER_IMAGE_REGISTRY` | `serve` | `off` stops the server reading the images clusters run from their registries: only builds node agents read from running containers are checked (1.20.1 and later). See [Running images](../usage/kubernetes.md#running-images). |
| `DEACONGUARD_FEED_CACHE_MB` | `serve` | Memory, in MB, for advisory feeds kept parsed between scans; 400 by default, `0` to parse for every scan. See [Parsed feeds](../supported-distributions.md#parsed-feeds). |
| `DEACONGUARD_HOST_ROOT` | the agent | Where the host's root filesystem is mounted, such as `/host`. Checks run there, with the host's own tools. |
| `DEACONGUARD_HOSTNAME` | the agent | The name the agent reports, such as a Kubernetes node's name. Otherwise the host's `/etc/hostname`, with `DEACONGUARD_HOST_ROOT`, or the machine's name. |
| `DEACONGUARD_ENROLL_TOKEN_FILE`, `DEACONGUARD_ENROLL_TOKEN` | `agent run` | A token to [enroll with by itself](../usage/agents.md#agents-that-enroll-themselves). |
