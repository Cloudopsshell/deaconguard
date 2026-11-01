---
title: Live detection
description: Find attacks on Linux machines, containers and Kubernetes nodes as they happen, with DeaconGuard's own watchers in the kernel. What it watches, what it doesn't, what it needs and what it costs.
---

Scans tell you what a machine looks like when they run. **Live detection** watches it all the time: the agent loads small watchers into the Linux kernel that see every program that starts and every write to a few sensitive files, as it happens, and its rules raise an alert within seconds when something looks like an attack.

It needs the DeaconGuard agent 1.27.0 or later, and it's on by default: upgrade the agents and it starts. The watchers, the code that loads them and the rules are all DeaconGuard's own; nothing else sits between the agent and the kernel.

## Where it runs

The watchers run in the machine's kernel, which every container on the machine shares, so one agent sees the machine and all its containers. Nothing is installed in the containers.

| Where | Watched? | How |
| --- | --- | --- |
| Linux servers: virtual machines, cloud instances, bare metal | Yes | The agent |
| Docker and Podman containers, Docker Compose services | Yes | The agent on their machine |
| Kubernetes nodes and their pods (EKS, GKE, AKS and others on ordinary nodes) | Yes | The [node agent](../installation/kubernetes.md) DaemonSet; the cluster agent alone can't, as it only talks to the Kubernetes API |
| Serverless containers: AWS Fargate, GKE Autopilot, Cloud Run, Azure Container Instances | No | No agent can run on their machines |
| Sandboxed containers: gVisor, Kata Containers, Firecracker | No | Each has a kernel of its own, which the machine's agent can't see into |
| Docker Desktop on a Mac or Windows | No | Its containers run in a hidden virtual machine without the agent |
| Macs and Windows machines | No | The watchers are Linux's |
| Linux older than 5.8 | No | The watchers need the kernel's ring buffer, new in 5.8; scans still run |

With a server installed with [Docker Compose](../installation/docker.md), its machine is watched when the Compose file's optional agent runs (`docker compose --profile agent up -d`). In an alert from a container, the alert names the program; naming the container and the pod is planned for a later release.

## Is it running?

Every agent reports every 15 seconds. On the dashboard:

- The **Hosts** list has a **Live detection** column, and a cluster shows how many of its nodes are watched, such as **Live on 2 of 2 nodes**.
- The **Dashboard** has a **Live detection** card: how many hosts are watched, and why each other one isn't.
- Each host has a **Runtime** tab with its state, since when, the agent's last report, and four numbers: the events the watchers looked at in the last hour (proof that it's watching), the last day's alerts, missed events, and the agent's CPU and memory.

| State | Meaning | What to do |
| --- | --- | --- |
| **Live** | Watching | Nothing |
| **Stopped** | It was running and stopped, with the reason: the agent stopped reporting, or the kernel refused something | Look at the reason and the agent's log on the host's page; the agent restarts it after a minute |
| **Off** | An administrator turned it off for this host | **Turn on**, on the Runtime tab |
| **Not supported** | The machine can't run it, with the reason: an old kernel, a Mac, or an agent without the rights to load the watchers | See [Where it runs](#where-it-runs) |
| **Agent too old** | The agent is older than 1.27.0 | [Upgrade the agent](../installation/upgrade.md#which-agents-to-upgrade) |
| **Starting** | Waiting for the agent's first report | Wait 15 seconds |

**Missed events** counts events the kernel dropped because the agent fell behind, and alerts left out over the limit of 30 a minute. It stays at 0 on all but very busy machines.

**Send a test alert**, on the Runtime tab (operators and admins), proves the whole chain: the agent starts a harmless program (a copy of `true`) from a temporary folder, the watchers see it start, the rule for programs in temporary folders matches it, and a **Test** alert arrives on the tab within about 20 seconds, and on the notification channels that tick **Runtime alerts**. Test alerts don't count as alerts. If the machine's temporary folders don't allow running programs, the tab says so.

**Turn off** and **Turn on** (admins) stop and start it for one host; the audit log records who did.

To be told when it stops, tick **Live detection stopped** on a [notification channel](./notifications.md#events): it's sent when a host where it was running stops, including when its agent stops checking in.

## What it detects

### Programs that start

| Rule | Alert | Severity |
| --- | --- | --- |
| `DG-RT-001` | A program starts from `/tmp`, `/var/tmp` or `/dev/shm`, or from memory without a file. Attackers put their tools there because anyone can write to them | High |
| `DG-RT-002` | A shell starts under a server that has no reason to run commands: nginx, Apache, lighttpd, Caddy, PHP-FPM, MySQL, MariaDB, Redis, MongoDB, Memcached or uWSGI. It's how a web shell, an injected command or an exploited service shows | Critical |
| `DG-RT-003` | A program with a crypto miner's name, or given a mining pool's address (`stratum+tcp://`), starts | Critical |
| `DG-RT-004` | A shell runs a command that downloads a script and pipes it into a shell, such as `curl … \| sh`, with no person at a terminal: from a scheduled job, a service or a script | High |

Programs that `go test` and `go run` build in `/tmp/go-build…` aren't reported for `DG-RT-001` when the `go` tool starts them, as it does on every build machine. PostgreSQL isn't on the list for `DG-RT-002`, since its `archive_command` runs a shell by design. Typing `curl … | sh` yourself, at a terminal, isn't reported.

### Sensitive files that change

| Rule | Files | Severity |
| --- | --- | --- |
| `DG-RT-010` | Accounts and passwords: `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow` | High |
| `DG-RT-011` | Who may use sudo: `/etc/sudoers` and `/etc/sudoers.d/` | High |
| `DG-RT-012` | SSH logins: every account's `authorized_keys`, and `/etc/ssh/sshd_config` with `sshd_config.d/` | High |
| `DG-RT-013` | What runs on its own: `/etc/crontab`, `/etc/cron.*`, `/var/spool/cron/`, systemd unit folders, `/etc/rc.local`, and `/etc/ld.so.preload`, a library loaded into every program | High; Critical for `ld.so.preload` |

A file is reported when a program opens it for writing, renames another file onto it, or links it. The watchers see the attempt, before the kernel checks the program's rights, so an attempt that fails is reported too: someone trying to write to `sudoers` is worth knowing about either way. Changes made by the package manager (`apt`, `dpkg`, `dnf`, `yum`, `rpm`, `zypper`, `apk`, automatic updates) aren't reported. Changes made with the usual admin tools (`useradd`, `passwd`, `visudo`, `crontab`, `systemctl` and others) are, as **Medium**: most likely someone on your team, worth knowing.

A file written by a relative path, such as `passwd` from inside `/etc`, is reported when its name is one of those above; the agent reads the program's folder to place it, or names the file where it usually lives when the program has already exited.

### What it doesn't detect yet

Live detection starts with what most break-ins on servers do. It doesn't yet watch network connections (reverse shells, connections to mining pools), changes of user (a program becoming root outside sudo), kernel modules loaded at runtime, or one process attaching to another; these are planned, one release at a time, along with naming the container and pod of each alert and letting you allow what's expected on a host. Scans still cover what they always did, such as [host changes](./host-changes.md), malware on disk and [attack paths](./attack-paths.md).

An attacker who is already root on a machine can stop the agent, as they can any tool on it. Then the host's live detection shows **Stopped**, and **Live detection stopped** and **Agents offline** notifications are sent.

## Alerts

The same alert, by the same program for the same file, is sent once every 10 minutes; repeats in between are counted, and the next one says how many. At most 30 alerts a minute leave a machine. Alerts are kept 30 days, at most 5,000 per host.

To be told about alerts, tick **Runtime alerts** on a [notification channel](./notifications.md#events): critical alerts are sent as critical, the others as warnings, a report's alerts together in one message.

## What leaves the machine

Only alerts, and the status above. An alert holds the rule, the program and its command line (with anything that looks like a password or token masked), the program that started it, the account, the process ID, and for a file, its path. The watchers' events, and what programs read or write, stay on the machine.

## How light it is

- **In the kernel**, the watchers look at each program that starts and each file opened for writing. A write is compared with the watched paths eight bytes at a time and dropped there unless it's one of them, so the agent hears about every program start but only the few writes that matter. Files opened only for reading cost nothing.
- **The agent** reads the watchers' events from a ring buffer of 256 KB, the kernel's own one, and runs the rules on them. It only reads `/proc` for an event a rule already suspects.
- Measured on a test machine (Ubuntu 24.04, arm64): at rest, the agent used **20 ms of CPU a minute** (0.03% of one CPU) and **22 MB** of memory. Under a storm of 4,400 programs starting a second, with as many file writes, far busier than most servers, it used **about 3% of one CPU** and 26 MB, and the storm ran 2% slower than without it. The Runtime tab shows the agent's own numbers for each host.

The watchers use only the kernel's stable tracepoints, for system calls and for programs starting, which is why one build runs on every kernel from 5.8 on. The kernel checks each watcher before running it, so a watcher can't crash or hang the machine.

## What it needs

- Linux 5.8 or later, on `x86_64` or `arm64`.
- The agent running as root, as it does when installed with the install script or the packages. In Kubernetes and Docker Compose, the agent's container needs the `BPF` and `PERFMON` capabilities, which the Helm chart, the Kustomize base and the Compose file give it from 1.27.0.
- The kernel's tracing file system at `/sys/kernel/tracing`, which systemd mounts at boot; the agent mounts it when it isn't.
