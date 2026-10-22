---
title: Running containers
description: See the containers on your machines, Docker, Podman and Kubernetes nodes alike, and check the running ones for vulnerable packages and libraries.
---

The **Running containers** check (`containers`) lists the containers on a machine, running and stopped, and checks what is installed in each running one, the way DeaconGuard checks the machine itself: its OS packages against its distribution's advisories, and its [application libraries](./libraries-and-sbom.md) against OSV. It needs DeaconGuard 1.2.0 or later on the server and the agent.

```bash
deaconguard scan HOST_ID --checks packages,containers
```

or choose **Running containers** in the dashboard's scan dialog.

## Which containers

The agent asks the machine's own container tools, if they are installed:

| Runtime | Asked with |
| --- | --- |
| Docker | `docker ps` and `docker inspect` |
| Podman | `podman ps` and `podman inspect` (containers run by root) |
| containerd and CRI-O, such as Kubernetes nodes | `crictl ps` and `crictl inspect` |

From agent 1.8.0, they are asked for stopped containers too (`ps -a`), and for each container's state, when it was created, started and stopped, its exit code, restart count, user, whether it is privileged, its network, published ports and command. The agent also reads which user the container's main process actually runs as, from `/proc`. Up to 300 containers are listed.

A **stopped container is listed but not checked**: it has no running process whose files the agent could read. Check its image instead, on the [Images](./images.md) page or with `deaconguard image scan`.

On **Kubernetes**, the [agent DaemonSet](../installation/kubernetes.md) already has what it needs (`hostPID` and the node's root filesystem), so a scan of each node includes its pods' containers, named `namespace/pod/container`.

## Nothing inside a container is run

- The host's own `docker`, `podman` or `crictl` lists the containers, with fixed commands.
- The agent then **reads** each container's files itself, through `/proc/PID/root`: its `/etc/os-release`, its package database, and its package-manager files. It never starts, stops, enters or changes a container, and never runs a program from one.
- It **never follows a symbolic link** inside a container, in a file or in any folder on the way. A container could otherwise point a link at a file on the host, such as `/etc/shadow`, and make the agent, which runs as root, read it. When a file is a link, such as `/etc/os-release` in most images, the real file it stands for is read instead (`/usr/lib/os-release`).
- Volumes mounted into a container are left out; the machine's own scan covers what is on the host.
- The other way round, the machine's own [library check](./libraries-and-sbom.md) skips container storage (`/var/lib/docker`, `/var/lib/containerd`, `/var/lib/containers`, `/var/lib/kubelet`, and k3s's and RKE2's containerd), from 1.8.0. Before, image layers there were reported as the machine's own libraries, under storage paths such as `/var/lib/containerd/…/snapshots/9/fs/…` and without saying which container they belonged to. This check reports them under each container, with the path inside it.

This needs root, which the agent has. A local `deaconguard serve` that doesn't run as root reports the check as skipped.

## What is checked in each container

- **OS packages:** Debian and Ubuntu (`/var/lib/dpkg/status`, and `status.d` in distroless images), Alpine (`/lib/apk/db/installed`), and RHEL, Rocky, AlmaLinux, Oracle Linux, Fedora and Amazon Linux 2023 (`rpmdb.sqlite`, read directly; no `rpm` is needed on the host). The container must run a [supported distribution](../supported-distributions.md) release. Images with an RPM database in the older Berkeley DB or ndb format, such as RHEL 8 or SUSE, have only their libraries checked for now, and the container says so.
- **Release support:** whether the container's distribution still gets security fixes, as for machines.
- **Application libraries:** the same files as the [library check](./libraries-and-sbom.md), across the container's whole file system except `/usr/lib` and `/usr/share`. A project's `node_modules` is listed by its lock file, so it isn't walked.
- Images with no OS at all, such as `scratch` or distroless static images, have only their libraries checked.

Containers with the same contents, such as replicas of one image, are checked once.

## Scan new containers automatically

On an agent's host page, turn on **Scan new containers automatically** (operators and admins). The agent then looks at the running containers about once a minute; when new ones have started, it tells the server, which queues a Running containers scan of that machine. So a container you deploy is checked within about two minutes, without waiting for the next scheduled scan.

- It is **off** by default, per machine.
- At most **one automatic scan every 10 minutes** per machine, and none while another scan of it is waiting or running, so a machine that starts containers all the time, such as a CI runner, isn't scanned all the time. Containers that start in between are covered by the next one.
- Stopped containers don't trigger anything. The agent only counts container IDs; the scan itself reads the containers as described above.
- It needs agent 1.2.0 or later. The automatic scans appear in the scan history and the audit log, started by `server`.

Through the [API](../reference/api.md): `PATCH /api/hosts/{id}` with `{"auto_scan_containers": true}`.

## Results

The host's **Running containers** tab shows:

- **Totals:** running and stopped containers, images, vulnerabilities, those known to be exploited, and containers on a release past its end of life.
- **A row per container:** its name, runtime and ID; its state (running since when, or exited with which code and when) and restarts; its image, image ID, distribution and that release's support; how many packages and libraries it has; its vulnerabilities by severity and how many are known to be exploited; and who it runs as, marked when it is privileged. A container on a release DeaconGuard doesn't support, such as Debian 10 or Alpine before 3.18, says **OS packages not checked**; its libraries are still checked.
- **Findings:** the most urgent vulnerabilities across all containers, each with its container, its image and where in the container it was found (an OS package, or the path of the library's folder or lock file inside the container).

**Open a container** for its details (state, image, OS, runtime, command, user, privileged, network and ports, created and started) and **every vulnerability in it** as a tree:

- **OS packages** → each package and version, with the version that fixes it → its vulnerabilities;
- **Application libraries** → each folder or lock file inside the container, such as `/usr/local/lib/python3.11/site-packages` → each library and version → its vulnerabilities.

**Show** narrows it to vulnerabilities with a fix or known to be exploited, and **Group by** switches to severity. A package's fix is the lowest version that fixes all of its vulnerabilities above the installed one. A container keeps its 1,000 most urgent vulnerabilities; a note says when it had more. The opened container is in the page's address (`?container=ID`), so it can be linked. Results from a server before 1.8.0 list only the vulnerabilities with a fix or known to be exploited.

The same findings, named after their container, are in [reports](./reports.md). Through the API, each container in the result has `findings` (those with a fix or known to be exploited, at most 300) and `vulnerabilities` (all of them, at most 1,000), each with `container`, `image`, `source` (`os` or `library`), `package`, `version`, `ecosystem`, `fixed`, `fixable`, `exploited` and `paths`.

The fix for a container is almost always a **new image**: rebuild it from an updated base image, or update the package in its Dockerfile, then redeploy. Updating packages inside a running container is lost when it restarts.
