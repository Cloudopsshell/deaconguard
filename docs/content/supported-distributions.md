---
title: Supported distributions
description: Which Linux distributions DeaconGuard scans, the advisory data it uses for each, and how it tells you a release is past its end of life.
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

All on **amd64 and arm64**. Advisory checks DeaconGuard can't evaluate are listed with the scan, never treated as clean.

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
- **Alpine** is planned, together with container scanning, in a later release.
- **openSUSE Tumbleweed**, **Amazon Linux 2**, and other distributions and releases not listed above. The install script won't set up an agent on them.

The server itself can run on any of the distributions above; only the machines you scan need a supported release.

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

## What a report covers

Package reports cover the packages installed through DPKG or RPM, and the running kernel where the distribution's feed supports it. They don't cover applications installed outside the package manager, or containers.

The optional checks look for common signs of tampering and misconfiguration, not every possible compromise. **No report is a claim that a machine is secure.**
