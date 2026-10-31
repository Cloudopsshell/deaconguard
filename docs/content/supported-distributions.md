---
title: Supported distributions
description: Which Linux distributions and macOS releases DeaconGuard scans, the advisory data it uses for each, and how it tells you a release is past its end of life.
---

| Distribution | Versions | Advisory data |
| --- | --- | --- |
| Ubuntu LTS | 18.04, 20.04, 22.04, 24.04, 26.04 | Canonical CVE OVAL: packages and the running kernel. |
| Debian | 12 (Bookworm), 13 (Trixie) | Debian Security Tracker: source-package status and fixed versions. |
| Red Hat Enterprise Linux | 8, 9 | Red Hat's official OVAL feeds. |
| Rocky Linux | 8, 9, 10 | Rocky's errata (`updateinfo`) from the BaseOS and AppStream repositories. |
| AlmaLinux | 8, 9, 10 | AlmaLinux's OVAL errata. |
| Oracle Linux | 8, 9, 10 | Oracle's ELSA OVAL. |
| Fedora | 40 and later | Fedora's security updates (`updateinfo`) from the updates repository, and from the archive once a release ends. |
| openSUSE Leap | 15.6, 16.0 | SUSE's CVE OVAL. |
| SUSE Linux Enterprise Server and Desktop | 15 SP6 and later, 16 | SUSE's CVE OVAL. |
| Amazon Linux | 2023 | ALAS RSS and bulletins, with replacement RPM versions. AWS notes that bulletin pages and repository metadata can briefly disagree. |
| Alpine Linux | 3.18 and later | Alpine's security database (secdb) for the main and community repositories. It lists only vulnerabilities Alpine has fixed, so ones it hasn't fixed yet aren't reported. Alpine rates nothing, so severities are each CVE's CVSS v3 score from [OSV](https://osv.dev), or unknown when no score is published. |

All on **amd64 and arm64**. Advisory checks DeaconGuard can't evaluate are listed with the scan, never treated as clean.

## macOS

DeaconGuard checks **macOS 10.15 and later**, on Apple silicon and Intel, from DeaconGuard 1.8.0. A Mac has no package list to match against advisories: Apple updates macOS whole, and publishes what each update fixes, but not in a form to match against what's installed. So for a Mac, DeaconGuard reports:

- whether its **macOS release still gets security updates**, from [endoflife.date](https://endoflife.date/macos), since Apple announces no end dates (it supports about the three newest releases);
- each **newer version of its release** that's out, as a high finding, since Apple fixes flaws in every point release, some exploited before the fix;
- the **updates the Mac has already found** but not installed, from `softwareupdate --list --no-scan`, such as Safari or Command Line Tools.

The [macOS baseline](./usage/audits.md#the-deaconguard-macos-baseline) checks FileVault, System Integrity Protection, Gatekeeper, XProtect, the firewall, sharing, accounts and update settings. File integrity, running containers, and the ClamAV and YARA scans are for Linux and don't run on Macs; the dashboard doesn't offer them there.

## Packages from other repositories

On Rocky Linux, AlmaLinux, Oracle Linux and SUSE, a finding needs the package to be **signed by the distribution**. Agents report each RPM package's signing key, so a package with the same name from a third-party repository isn't matched against the distribution's advisories. Agents before 0.19.0 don't report keys: their packages are assumed to be the distribution's, and the scan's coverage says so.

## Release lifecycle

Every scan says whether the release still gets security fixes from its vendor, from the vendor's published dates. Fedora's come from Fedora's update system, Bodhi, at scan time.

| State | Means | Audit grade |
| --- | --- | --- |
| **Supported** | Security fixes for everyone, until the date shown. | — |
| **Extended support** | Regular support ended. Fixes continue only through Ubuntu Pro (ESM), Debian LTS or SUSE LTSS. | B at most |
| **End of life** | No more security fixes. New vulnerabilities aren't fixed, or even published, for the release, so a scan that finds little proves little. | D at most |
| **Unknown** | DeaconGuard has no date for the release yet, such as Debian 13 and SUSE Linux Enterprise 16. Check the vendor's lifecycle page. | — |

The dashboard lists hosts past regular support. The hosts list and each host's page show a badge, and the scan page and [reports](./usage/reports.md) show the release's support with a link to the vendor's lifecycle page. Scans from before 0.19.0 don't have it until the host is scanned again.

## Not supported

- **CentOS Stream 9 and 10** are recognised but deliberately rejected: their official repositories publish no `updateinfo` metadata, and RHEL OVAL isn't assumed to match them.
- **RHEL 10** isn't enabled yet: no official RHEL 10 feed was present in Red Hat's feed index.
- **openSUSE Tumbleweed**, **Amazon Linux 2**, and other distributions and releases not listed above. The install script won't set up an agent on them.

### Releases that have ended

Debian 11 and earlier, Alpine before 3.18, CentOS Linux 7 and 8, CentOS Stream 8, Amazon Linux 2, openSUSE Leap before 15.6 and Fedora before 40 no longer get security fixes, so their vendors publish no advisories to check packages against. From 1.8.1, DeaconGuard says so instead of only "unsupported":

- A **container** or **image** on one gets a high finding, `DG-EOL-001`, with the release, the date it ended and the release to rebuild on, and an **End of life** badge. Its libraries are still checked. An image scan with `--fail-on high` fails on it.
- A **machine** on one isn't scanned; the scan's error says when the release ended and what to upgrade to.

The server itself can run on any of the distributions above except Alpine; only the machines you scan need a supported release.

**Alpine machines:** the install script and packages need systemd, which Alpine doesn't use, so they don't set up an agent there. Run `deaconguard agent enroll` and `deaconguard agent run` from the [release archive](./installation/manual-install.md) under your own OpenRC service, or run the agent's [container image](./installation/docker.md). Alpine is most common inside containers, which DeaconGuard will scan in a coming release.

## Parsed feeds

Some feeds are large: Canonical's OVAL for one Ubuntu release is hundreds of megabytes of XML, and reading it takes several seconds of CPU, half a minute on a small server. A feed changes at most every 12 hours, so the server reads each one once and keeps it, parsed, for the scans that follow, machines' and images' alike: a second scan of the same release takes a fraction of a second. This applies to Ubuntu's, Debian's, Red Hat's, AlmaLinux's, Oracle Linux's and SUSE's feeds, and Rocky Linux's and Fedora's updateinfo; the others are small enough to read each time.

- **Memory:** parsed feeds take up to about 400 MB, roughly what one Ubuntu release (about 275 MB) takes with Debian's and Red Hat's; under a memory limit lower than 1 GB, such as a small container's, at most 40% of it. Before a feed is read, the ones used least recently are let go until it fits beside the others, so two large feeds are never held while a third is read; a feed let go is read again when a scan needs it. A feed is also let go after 30 minutes without a scan, and a new download replaces the old one.
- **Changing it:** `DEACONGUARD_FEED_CACHE_MB` sets the budget, such as `700` to keep two Ubuntu releases when the server scans both, or `0` to read the feed for every scan, as before 1.17.0. With Helm, `server.feedCacheMB`. Keep it well under the server's memory limit, which needs about 450 MB more while a feed is read.
- **Memory limit:** the server tells the Go runtime the memory limit it runs under, a container's or a systemd unit's `MemoryMax`, and keeps its heap under 85% of it (1.20.3 and later), so it collects memory rather than being stopped by the kernel. `GOMEMLIMIT`, if you set it, is used instead.

## Feed hosts

The server downloads the advisory data, so it needs HTTPS access to the hosts for the distributions you scan:

| Distribution | Hosts |
| --- | --- |
| Ubuntu | `security-metadata.canonical.com` |
| Debian | `security-tracker.debian.org` |
| Red Hat Enterprise Linux | `security.access.redhat.com` |
| Rocky Linux | `dl.rockylinux.org` |
| AlmaLinux | `security.almalinux.org` |
| Oracle Linux | `linux.oracle.com` |
| Fedora | `dl.fedoraproject.org`, `archives.fedoraproject.org`, `bodhi.fedoraproject.org` |
| openSUSE, SUSE Linux Enterprise | `ftp.suse.com` |
| Amazon Linux | `alas.aws.amazon.com` |
| Alpine Linux | `secdb.alpinelinux.org`, and `api.osv.dev` for severities (only CVE IDs are sent) |

## What a report covers

Package reports cover the packages installed through DPKG or RPM, and the running kernel where the distribution's feed supports it. They don't cover applications installed outside the package manager, or containers.

The optional checks look for common signs of tampering and misconfiguration, not every possible compromise. **No report is a claim that a machine is secure.**
