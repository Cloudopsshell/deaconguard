---
title: Running containers
description: Check the containers running on your machines, Docker, Podman and Kubernetes nodes alike, for vulnerable packages and libraries.
---

The **Running containers** check (`containers`) finds every container running on a machine and checks what is installed in each one, the way DeaconGuard checks the machine itself: its OS packages against its distribution's advisories, and its [application libraries](./libraries-and-sbom.md) against OSV. It needs DeaconGuard 1.2.0 or later on the server and the agent.

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

Up to 300 running containers are checked. Stopped containers and images that aren't running are not; checking images in registries comes in a later release.

On **Kubernetes**, the [agent DaemonSet](../installation/kubernetes.md) already has what it needs (`hostPID` and the node's root filesystem), so a scan of each node includes its pods' containers, named `namespace/pod/container`.

## Nothing inside a container is run

- The host's own `docker`, `podman` or `crictl` lists the containers, with fixed commands.
- The agent then **reads** each container's files itself, through `/proc/PID/root`: its `/etc/os-release`, its package database, and its package-manager files. It never starts, stops, enters or changes a container, and never runs a program from one.
- It **never follows a symbolic link** inside a container, in a file or in any folder on the way. A container could otherwise point a link at a file on the host, such as `/etc/shadow`, and make the agent, which runs as root, read it. When a file is a link, such as `/etc/os-release` in most images, the real file it stands for is read instead (`/usr/lib/os-release`).
- Volumes mounted into a container are left out; the machine's own scan covers what is on the host.

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

The scan's **Running containers** tab lists every container with its image, runtime, distribution and its support, how many packages and libraries it has, its vulnerabilities by severity, how many are known to be exploited, and how many an update of the image fixes. Open a container to see what to fix: each vulnerability that has a fixed version or is known to be exploited, most urgent first. The same findings, named after their container, are in [reports](./reports.md) and the API.

The fix for a container is almost always a **new image**: rebuild it from an updated base image, or update the package in its Dockerfile, then redeploy. Updating packages inside a running container is lost when it restarts.
