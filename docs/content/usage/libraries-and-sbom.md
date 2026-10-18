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
| Go | `go.mod` |
| Ruby (RubyGems) | `Gemfile.lock` |
| Rust (crates.io) | `Cargo.lock` |
| PHP (Packagist) | `composer.lock` |

- **Skipped on purpose:** `/usr/lib`, `/usr/libexec` and `/usr/share`. Libraries there come from the distribution's own packages, which the [package check](../checks.md) already covers with the distribution's advisories. OSV doesn't know about the fixes distributions back-port, so checking those copies would report fixed problems. Kernel and device file systems, `.git` folders and libraries nested inside other libraries' `node_modules` are skipped too.
- **Limits:** files up to 4 MB, at most 5,000 files and 50,000 libraries per machine. A note says when a limit was reached.
- **Read-only:** one fixed command finds and reads the files; nothing is run or changed. With root (or sudo), it can read every user's projects; without, the result is marked partial.
- Dependencies from git, a local path or a URL can't be matched by version, so they're left out.

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
