---
title: Images in CI/CD pipelines
description: Check a container image, an image archive or a project folder in a pipeline, fail the build on what matters, and publish SARIF, JUnit or SBOM reports.
---

`deaconguard image scan` checks an image in a pipeline, before it is pushed or deployed, and [`deaconguard config scan`](./config-checks.md) checks its Dockerfile and Kubernetes manifests. It reads the image as data and never runs it, so it needs no Docker daemon, no root and no DeaconGuard server. It needs DeaconGuard 1.4.0 or later.

## What it can check

| Argument | What it reads |
| --- | --- |
| `nginx:1.27`, `ghcr.io/acme/shop:4.2` | An image in its registry. See [Images in registries](./images.md). |
| `image.tar`, `docker-archive:image.tar` | An archive from `docker save` or `podman save`, compressed with gzip or not. |
| `oci:layout/`, `oci:image.tar` | An OCI image layout, a folder or a tar of one, as `docker buildx build --output type=oci`, `buildah push` or `skopeo copy` write it. `--platform` picks one of several platforms. |
| `dir:path/` | A folder: an image's unpacked files, a chroot, or a project. Its OS packages are checked when it has a package database, and its lock files (`package-lock.json`, `requirements.txt`, `go.mod`, `Cargo.lock` and the others in [Libraries](./libraries-and-sbom.md#what-it-looks-at)) against OSV. |

Without a prefix, a path that exists is read as what it holds: an archive with `manifest.json` is a `docker save` archive, one with `index.json` and `oci-layout` an OCI layout, and a plain folder a folder. Anything else is an image name.

Archives and layouts are checked like registry images: layers named by digest must match it. Symbolic links in a folder are never followed outside it.

```bash
docker build -t shop:ci .
docker save shop:ci -o shop.tar
deaconguard image scan shop.tar --fail-on high
```

## Failing the build

`--fail-on critical`, `high`, `medium` or `low` makes the command exit with status **4** when the image has a vulnerability at or above that severity, so the pipeline stops. Vulnerabilities with no published severity don't count.

`--ignore-unfixed` counts, and reports, only the vulnerabilities an update fixes or attackers are known to use. A vulnerability with no fix yet can't be fixed by rebuilding, so it doesn't fail the build.

| Exit status | Means |
| --- | --- |
| 0 | Checked; nothing at or above `--fail-on` |
| 4 | Checked; vulnerabilities at or above `--fail-on` |
| 1 | Not checked: the image couldn't be read, or an option is wrong |

## Reports

`--format` chooses what the command writes, and `--output FILE` writes it to a file and keeps the summary in the job's log:

| `--format` | For |
| --- | --- |
| `table` | People: the summary and what to fix (the default) |
| `json` | Scripts: the result and every vulnerability, with `fixable` and `known_exploited` |
| `sarif` | SARIF 2.1.0 for GitHub code scanning, GitLab, Azure DevOps and other code-scanning tools: one result per vulnerability and package, with GitHub's `security-severity` |
| `junit` | JUnit XML for GitLab, Jenkins, Bitbucket and Azure DevOps test reports: a test case per vulnerability; those at or above `--fail-on` fail |
| `cyclonedx`, `spdx` | A software bill of materials of the image's packages and libraries: CycloneDX 1.6 or SPDX 2.3 JSON, as for [hosts](./libraries-and-sbom.md#download-an-sbom) |

```bash
deaconguard image scan shop.tar --ignore-unfixed --fail-on high --format sarif --output deaconguard.sarif
deaconguard image scan shop.tar --format cyclonedx --output shop.cdx.json
```

Progress goes to standard error, so a report on standard output can be piped.

## What leaves the machine

Only what any image check sends: OS package checks use the [advisory data](./vulnerabilities.md) DeaconGuard downloads, and libraries are checked against OSV, which is sent their names and versions. The image itself, and its files, stay where they are. To scan without these downloads on each run, cache `$DEACONGUARD_HOME` (by default `~/.local/share/deaconguard` for a user) between jobs: it holds the advisory data and the [layer cache](./images.md#nothing-in-the-image-is-run).
