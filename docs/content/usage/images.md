---
title: Images in registries
description: Check container images in Docker Hub, GHCR, Quay, Harbor and other registries before they run, without pulling or running them.
---

DeaconGuard checks container images **where they are stored**, before anything runs them: their OS packages against their distribution's advisories, their [application libraries](./libraries-and-sbom.md) against OSV, and their release support, as for [running containers](./containers.md). It needs DeaconGuard 1.3.0 or later.

```bash
deaconguard image scan nginx:1.27
deaconguard image scan ghcr.io/acme/shop:4.2 --platform linux/arm64
```

## Nothing in the image is run

DeaconGuard reads an image the standard way, through the registry API that `docker pull` uses, as data:

1. It asks the registry for the image's **manifest**, the list of its layers. For an image built for several platforms, it picks one: the machine's own (`linux/amd64` or `linux/arm64`), or the one given with `--platform`.
2. It downloads each **layer**, a compressed archive, and reads it as it arrives. It keeps only the files that say what is installed: `/etc/os-release`, the package database (dpkg, apk, or RPM's `rpmdb.sqlite`) and package-manager files such as lock files. Everything else passes through and is thrown away. Later layers replace and delete files of earlier ones, as when the image runs.
3. Each layer is **checked against its digest**, the SHA-256 the manifest names. A layer that doesn't match is rejected, and the scan fails.

No container is created and nothing in the image is executed. Docker isn't needed.

**Layer cache:** what was read from each layer is kept by its digest in `/var/lib/deaconguard/feeds/layers/` (at most 2 GB, least recently used first). Images that share base layers, such as everything built `FROM debian:12`, read them once; scanning an image again downloads only the manifest.

## Registries and logins

Any registry that implements the standard registry API works: Docker Hub, GitHub's GHCR, Quay, Harbor, GitLab, Google Artifact Registry, Azure Container Registry, Amazon ECR, a self-hosted `registry`. Public images need no login.

For a private image, give a login (a username and a token or password with **pull** access) in the environment:

```bash
DEACONGUARD_REGISTRY_USERNAME=robot \
DEACONGUARD_REGISTRY_PASSWORD="$(cat token)" \
deaconguard image scan registry.example.com/team/app:2.1
```

DeaconGuard sends it only to the image's registry, or to the login service that registry names, and asks only to pull.

## The result

```text
Image: nginx:1.27
Digest: sha256:… (linux/amd64)
OS: Debian 12 (bookworm), 149 packages
Release support: Regular support ended 10 June 2026; security fixes need Debian LTS, until 30 June 2028
Libraries: 0
Vulnerabilities: 734 (142 low, 592 unknown); 258 fixed by a newer image, 1 known to be exploited
  LOW  nginx 1.27.5-1~bookworm (Debian 12 (bookworm)): CVE-2023-44487 · Fixed in …: update the image. Known to be exploited (CISA KEV).
```

It lists each vulnerability with a fix or known to be exploited, most urgent first. `--json` prints it all as JSON.

**In a pipeline:** `--fail-on high` (or `critical`, `medium`, `low`) exits with status **4** when the image has a vulnerability at or above that severity, so a build can stop before the image is pushed or deployed.

## Limits

- Images with an RPM database in Berkeley DB or ndb format (RHEL 8, SUSE) have only their libraries checked for now.
- Static images with no package database, such as Go binaries on `scratch`, have only their package-manager files checked.
- Layers up to 8 GB; files larger than the [library check](./libraries-and-sbom.md#what-it-looks-at) reads are skipped, and the result says so.
