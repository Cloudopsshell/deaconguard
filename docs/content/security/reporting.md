---
title: Reporting a vulnerability
description: How to report a security problem in DeaconGuard.
---

Please report security problems **privately**, not in a public issue:

1. Open [a private security advisory](https://github.com/Cloudopsshell/deaconguard/security/advisories/new) on GitHub. Only the maintainers can see it.
2. If you can't use GitHub, email **opensource@cloudopsshell.com** with "DeaconGuard security" in the subject.

Include the DeaconGuard version (`deaconguard version`), how to reproduce the problem, and what an attacker could achieve. You'll receive an acknowledgement within a few working days. We agree a disclosure date with you, publish a fixed release, and credit you in the advisory unless you prefer otherwise.

Security fixes are released for the latest minor version.

## Scope

**In scope:** DeaconGuard itself: the commands it runs on scanned machines, its use of sudo, the server and its API, the agent, the dashboard, the data directory, the install script and the release files.

**Out of scope:** vulnerabilities DeaconGuard reports on your machines (report those to the affected software), and errors in the distributions' advisory data (report those to the distribution).
