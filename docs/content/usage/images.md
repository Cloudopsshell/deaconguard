---
title: Images in registries
description: Check container images in Docker Hub, GHCR, Quay, Harbor and other registries before they run, from the dashboard or the command line, without running them.
---

DeaconGuard checks container images **where they are stored**, before anything runs them: their OS packages against their distribution's advisories, their [application libraries](./libraries-and-sbom.md) against OSV, and their release support, as for [running containers](./containers.md). It needs DeaconGuard 1.3.0 or later.

Check images from the dashboard's **Images** page, where the server keeps each image's results and history, or from the command line, in a pipeline for example:

```bash
deaconguard image scan nginx:1.27
deaconguard image scan ghcr.io/acme/shop:4.2 --platform linux/arm64
```

## In the dashboard

On **Images**, **Add image** takes an image's name, as in `docker pull`, and a platform (`linux/amd64` unless you choose another), and checks it at once. Each image shows its last scan, its vulnerabilities, those known to be exploited and how many a newer image fixes. **Scan now** checks it again; an image's page shows its latest result, what to fix first, and its last 20 scans with their digests, so you can see when the tag moved to a new build.

The server reads the image itself, one at a time, so the machine running DeaconGuard needs to reach the registry over HTTPS. A scan interrupted by a server restart is marked failed; scan it again.

Operators add, scan and remove images; viewers see the results. Removing an image deletes its results in DeaconGuard, never anything in the registry.

## Watch for new builds

A **watched** image is checked again without anyone pressing **Scan now**. Watching is on for new images, and **Stop watching** on the image's page turns it off.

- **New builds:** every 15 minutes, the server asks the registry which build the tag points to, with a `HEAD` request for the manifest: nothing is downloaded, and Docker Hub doesn't count it against its pull limits. When the tag has moved to a new build, the image is scanned again.
- **New vulnerabilities:** once a day, the image is scanned again for advisories published since. Unchanged layers come from the cache, so this takes a second or two.

The scan history says what started each scan: a person, `watch: new build pushed`, or `watch: daily rescan`. When the check fails, for example because the registry is rate-limiting or the login stopped working, the image says why, and the server log records it once.

New known exploited and critical vulnerabilities in an image, and failed scans, are sent to the [notification](./notifications.md) channels subscribed to those events, as for hosts.

**Scan on push from CI:** to scan an image the moment a pipeline pushes it, call the API with an operator's [API token](../reference/api.md#api-tokens) after the push:

```bash
curl -fsS -X POST -H "Authorization: Bearer $DEACONGUARD_TOKEN" \
  https://deaconguard.example.com/api/images/IMAGE_ID/scans
```

The image's ID is in its page's address.

## Nothing in the image is run

DeaconGuard reads an image the standard way, through the registry API that `docker pull` uses, as data:

1. It asks the registry for the image's **manifest**, the list of its layers. For an image built for several platforms, it picks one: the machine's own (`linux/amd64` or `linux/arm64`), or the one given with `--platform`.
2. It downloads each **layer**, a compressed archive, and reads it as it arrives. It keeps only the files that say what is installed: `/etc/os-release`, the package database (dpkg, apk, or RPM's `rpmdb.sqlite`) and package-manager files such as lock files. Everything else passes through and is thrown away. Later layers replace and delete files of earlier ones, as when the image runs.
3. Each layer is **checked against its digest**, the SHA-256 the manifest names. A layer that doesn't match is rejected, and the scan fails.

No container is created and nothing in the image is executed. Docker isn't needed.

**Layer cache:** what was read from each layer is kept by its digest in `/var/lib/deaconguard/feeds/layers/` (at most 2 GB, least recently used first). Images that share base layers, such as everything built `FROM debian:12`, read them once; scanning an image again downloads only the manifest.

## Registries and logins

Any registry that implements the standard registry API works: Docker Hub, GitHub's GHCR, Quay, Harbor, GitLab, Google Artifact Registry, Azure Container Registry, Amazon ECR, a self-hosted `registry`. Public images need no login.

For a private image, DeaconGuard needs a login for its registry: a username and a token or password with **pull** access. Prefer a read-only token where the registry offers one.

**In the dashboard**, an admin saves it under **Images**, **Registry logins**: the registry's host (`docker.io`, `ghcr.io`, `registry.example.com:5000`), the username and the token. It is used for every image in that registry. The server stores it in its database and never shows it again; to change it, edit the login and type a new one, or leave it empty to keep the saved one. A saved token is never sent to another registry: changing a login's registry needs the token again. The audit log records who added, changed or deleted each login, without the token.

What to save for the cloud registries:

| Registry | Host | Login |
| --- | --- | --- |
| Amazon ECR | `123456789012.dkr.ecr.eu-north-1.amazonaws.com` | Choose **An AWS access key**, and give an access key ID and secret access key of an IAM user with only the `AmazonEC2ContainerRegistryReadOnly` policy. ECR's registry passwords last 12 hours, so DeaconGuard keeps the key and gets a new password from the ECR API when it needs one. |
| Google Artifact Registry | `europe-north1-docker.pkg.dev` | Username `_json_key`, and as the password the JSON key of a service account with the **Artifact Registry Reader** role. |
| Azure Container Registry | `myregistry.azurecr.io` | A [repository-scoped token](https://learn.microsoft.com/azure/container-registry/container-registry-repository-scoped-permissions) with `content/read`, or a service principal's application ID and secret with the **AcrPull** role. |
| GitHub (GHCR) | `ghcr.io` | Your GitHub username and a personal access token (classic) with only `read:packages`. |
| Docker Hub | `docker.io` | Your username and a personal access token with **Read-only** access. A login also raises Docker Hub's pull limits. |

**On the command line**, give it in the environment:

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
