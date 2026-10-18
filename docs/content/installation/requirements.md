---
title: Requirements
description: Operating systems, accounts and network access DeaconGuard needs.
---

## Machines

- **Linux on amd64 or arm64**, running a [supported distribution](../supported-distributions.md), with **systemd** for the services.
- DeaconGuard is a single self-contained binary. The install script also installs the tools its checks use: ClamAV, YARA-X, procps, iproute2, findutils, and on the RHEL family and Fedora `needs-restarting` (with EPEL enabled on RHEL and its rebuilds for ClamAV). See [Install script](./install-script.md#what-the-script-does).
- The install script needs `curl`, `sha256sum`, and root: run it with `sudo`, or as root.
- For the antivirus scan: about 110 MB of disk for ClamAV's signatures, and about 1.5 GB of free memory and swap during a scan. The advanced scan adds about 30 MB for YARA-X and, while it runs, about 200 MB of memory for the rules.

- **The server needs at least 1 GB of memory**, RAM plus swap. It checks each machine's package list against the distribution's feed, one machine at a time; for an Ubuntu 24.04 machine that briefly needs about 450 MB (1.6 GB before DeaconGuard 0.5.2, so upgrade small servers). With too little, Linux stops the server mid-scan, and the dashboard says so. To add swap on a small server:

  ```sh
  sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile
  echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
  ```

The server can run on any [supported distribution](../supported-distributions.md). Agents only install on distributions DeaconGuard can scan.

The macOS builds run the server and the CLI, but cannot scan the Mac itself.

The server also runs in a container, with [Docker or Compose](./docker.md) or in [Kubernetes](./kubernetes.md), where an agent DaemonSet scans every node. An agent in a container scans its host with the host's own tools, so the host needs them installed as it would for an installed agent.

## Accounts

| Component | Runs as | Why |
| --- | --- | --- |
| Server (`deaconguard-server`) | its own `deaconguard` system user | It only needs its data directory and its port. |
| Agent (`deaconguard-agent`) | root | A security scanner has to see every process, system file and firewall rule. |
| Local mode, CLI | your user | Optional checks see more when [sudo is allowed](../checks.md#running-checks-with-sudo). |

## Network

| From | To | Port | Purpose |
| --- | --- | --- | --- |
| Browsers | Server | 8443/tcp | Dashboard |
| Agents | Server | 8443/tcp, or the [agent port](../security/securing-the-dashboard.md#give-agents-their-own-port) if you set one | Enrollment, receiving scans, sending results |
| Server | Distribution advisory feeds ([hosts](../supported-distributions.md#feed-hosts)) | 443/tcp | Security data, and Fedora's release dates |
| Server | `www.cisa.gov`, `epss.empiricalsecurity.com` | 443/tcp | [Exploit data](../usage/vulnerabilities.md): CISA KEV and EPSS |
| Server | Your mail server, Slack, Teams or webhook addresses | Their ports, such as 587/tcp or 443/tcp | [Notifications](../usage/notifications.md), when you set them up |
| Machines being installed | GitHub, `get.deaconguard.io` | 443/tcp | Downloading the package (install time only) |

Agents need **no inbound ports** and no internet access after installation.
