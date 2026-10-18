---
title: Versions and releases
description: How DeaconGuard is versioned and where to find release notes.
---

DeaconGuard follows [Semantic Versioning](https://semver.org): `MAJOR.MINOR.PATCH`.

- **Patch** releases (`1.0.0` → `1.0.1`) contain only fixes, including security fixes.
- **Minor** releases (`1.0.x` → `1.1.0`) add features without breaking existing installs, scripts or API clients.
- **Major** releases (`1.x` → `2.0.0`) are the only ones that may contain breaking changes, always listed with upgrade steps.
- Versions with a suffix, such as `1.1.0-rc.1`, are pre-releases for testing. GitHub marks them as pre-releases, and the install script installs them only when asked with `DEACONGUARD_VERSION`.

Every binary reports its version with `deaconguard version`, and every scan report records the version that produced it.

## Release notes

- [Releases on GitHub](https://github.com/Cloudopsshell/deaconguard/releases): files and notes for each version.
- [Changelog](https://github.com/Cloudopsshell/deaconguard/blob/main/CHANGELOG.md): every change, grouped by version, including upgrade steps and security fixes.

To be notified of new releases, use **Watch → Custom → Releases** on the [GitHub repository](https://github.com/Cloudopsshell/deaconguard).
