---
title: Application libraries and SBOM
description: Find vulnerable application libraries with OSV, and download a software bill of materials for every scan.
---

The **Application libraries** check (`libraries`) finds the libraries your applications use and checks them against [OSV](https://osv.dev), the open vulnerability database. Every scan can also be downloaded as a **software bill of materials** (SBOM): a list of every OS package and library on the machine. Both need DeaconGuard 1.1.0 or later on the server and on the agent.

## Run it

Choose **Application libraries** in the dashboard's scan dialog, or add `libraries` to `--checks`:

```bash
deaconguard scan HOST_ID --checks packages,libraries
```

It isn't part of a [server audit](./audits.md) yet, so audit grades don't change.

## What it looks at

The agent looks for the files package managers leave behind on `/`, `/home`, `/opt`, `/srv`, `/usr/local`, `/var/www` and `/root`:

| Ecosystem | Files |
| --- | --- |
| npm | `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` (Yarn 1 and later), `pnpm-lock.yaml`, and globally installed packages in `lib/node_modules` |
| Python (PyPI) | Installed packages (`*.dist-info` and `*.egg-info` in `site-packages` or `dist-packages`, virtualenvs included), `poetry.lock`, `Pipfile.lock`, and exact pins (`name==1.2.3`) in `requirements.txt` |
| Go | `go.mod`, and **compiled Go programs** (1.8.0 and later): see [Go programs](#go-programs) |
| Ruby (RubyGems) | `Gemfile.lock` |
| Rust (crates.io) | `Cargo.lock` |
| PHP (Packagist) | `composer.lock` |

- **Skipped on purpose:** `/usr/lib`, `/usr/libexec` and `/usr/share`. Libraries there come from the distribution's own packages, which the [package check](../checks.md) already covers with the distribution's advisories. OSV doesn't know about the fixes distributions back-port, so checking those copies would report fixed problems. Kernel and device file systems, `.git` folders and libraries nested inside other libraries' `node_modules` are skipped too.
- **Container storage is skipped** (1.8.0 and later): `/var/lib/docker`, `/var/lib/containerd`, `/var/lib/containers`, `/var/lib/kubelet`, k3s's and RKE2's containerd folders, Docker's snap and rootless Podman's `~/.local/share/containers`. The [Running containers](./containers.md) check reads each container and names it, with the path inside the container; a note on the result says which of these folders the machine has.
- **Limits:** files up to 4 MB, at most 5,000 files and 50,000 libraries per machine. A note says when a limit was reached.
- **Read-only:** one fixed command finds and reads the files; nothing is run or changed. With root (or sudo), it can read every user's projects; without, the result is marked partial.
- Dependencies from git, a local path or a URL can't be matched by version, so they're left out.

## Go programs

From 1.8.0, the check also reads **compiled Go programs**, such as `kubectl`, `terraform`, `helm`, k3s or your own services. Go 1.18 and later write into every program the Go version it was built with and the modules it contains. DeaconGuard reads that small block and checks:

- the **Go version**, as the module `stdlib`, which is how OSV lists Go's own vulnerabilities. For example, a program built with Go before 1.26.10 trusts certificates from the compromised eMudhra intermediate CAs ([GO-2026-6809](https://osv.dev/vulnerability/GO-2026-6809)) until it's rebuilt with a newer Go;
- each **module** the program was built with, at its version.

Where it reads them:

- **Machines:** programs under the same folders as above, on each folder's own file system. The distribution's own folders (`/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/usr/lib` and the like) and container storage (as above) are left out: distributions patch their Go programs without changing the Go version they record, and the package check covers them with the distribution's advisories. Programs from a vendor's own package repository, such as Docker's or HashiCorp's, install in `/usr/bin` and aren't read yet.
- **[Running containers](./containers.md) and [images](./images.md):** every program, read as the layers stream by; the distribution's folders are left out only when the image has a package database. Scratch and distroless images are read everywhere.

The agent reads each program itself, as a file, without following links; it never runs one. It reads at most 20,000 programs (16 GB) per machine, each up to 512 MB, for at most 10 minutes.

A program records its modules, not the packages it actually uses, so a finding means the program **contains** the vulnerable module, not necessarily that it calls the vulnerable code. Go's [govulncheck](https://go.dev/doc/tutorial/govulncheck) can tell, from the source. Go's vulnerability database publishes no severity scores, so Go findings show as unknown severity unless another source rates them.

## What is sent to OSV

The agent sends the list to your DeaconGuard server, and **only the server** talks to OSV. It sends `api.osv.dev` each library's **ecosystem, name and version**: no host names, addresses, file paths or anything else about your machines. The vulnerability records OSV returns are kept for a day in `/var/lib/deaconguard/feeds/osv/`. If you'd rather not send library names anywhere, leave the check off.

If OSV can't be reached, the check **fails** with the reason; it never reports a machine as clean when it couldn't check.

## Findings

Each vulnerable library is listed with:

- the OSV ID (such as `GHSA-35jh-r3h4-6jhm`) and the CVE, with a link to the record on osv.dev;
- the severity from the advisory, or computed from its CVSS v3 score;
- the versions that fix it;
- whether it is [known or likely to be exploited](./vulnerabilities.md) (CISA KEV and EPSS), as for packages;
- the files it was found in.

OSV often lists one vulnerability under several IDs, such as a GitHub advisory and a Python one. DeaconGuard shows it once. Known-exploited vulnerabilities come first, then by severity. Library findings appear in the scan, in [reports](./reports.md) and in the API; the dashboard's vulnerability lists, trends and [notifications](./notifications.md) still count OS packages only.

## Download an SBOM

Every scan from 1.1.0 on records its OS packages, and, when the library check ran, its libraries. On the scan's page, choose **SBOM (CycloneDX)** or **SPDX**, or from the command line on the server:

```bash
deaconguard sbom SCAN_ID > web-01.cdx.json
deaconguard sbom SCAN_ID --format spdx > web-01.spdx.json
```

or through the [API](../reference/api.md): `GET /api/scans/{id}/sbom?format=cyclonedx` (or `spdx`).

| Format | Version | File |
| --- | --- | --- |
| CycloneDX | 1.6, JSON | `deaconguard-HOST-DATE.cdx.json` |
| SPDX | 2.3, JSON | `deaconguard-HOST-DATE.spdx.json` |

Every component has a [package URL](https://github.com/package-url/purl-spec) (purl), such as `pkg:deb/ubuntu/openssl@3.0.13-0ubuntu3.4?arch=amd64&distro=ubuntu-24.04` or `pkg:npm/lodash@4.17.21`, so other SBOM tools can read it. Licences aren't included. Scans from before 1.1.0 have no SBOM: scan the machine again.
